using System.Buffers.Binary;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Channels;
using static System.Buffers.Binary.BinaryPrimitives;

namespace Tedd.HostMesh;

public interface ILinkEstimates
{
    long Capacity(ushort peer);
    int DelayMilliseconds(ushort peer) => 1;
}

public sealed class MeshRouter
{
    internal const int MaxBody = 850;
    internal const int HelloPeriod = 200, DeadInterval = 1100, Refresh = 900, MaxNeighbors = 28;
    private const byte Hello = 1, State = 2, Data = 3, InteractiveData = 4;
    private readonly object _gate = new();
    private readonly IMeshLinks _links;
    private readonly X509Certificate2 _key;
    private readonly TimeProvider _clock;
    private readonly Random _random;
    private readonly long _start;
    private readonly long _generation;
    private long _policyRevision;
    private long _sequence, _lastHello = -HelloPeriod, _lastState = -Refresh, _lastCredit;
    private readonly Dictionary<ushort, long> _heard = [];
    private readonly Dictionary<ushort, Row> _rows = [];
    private readonly Dictionary<ushort, (long Generation, long Sequence)> _versions = [];
    private readonly Queue<(ushort Peer, byte[] Packet)> _control = new(), _traffic = new();
    private readonly Channel<(ushort From, byte[] Payload)> _received = Channel.CreateBounded<(ushort, byte[])>(1024);
    private Dictionary<ushort, MeshRoute> _routes = [];
    private Dictionary<ushort, MeshRoute> _interactive = [];
    private readonly Dictionary<ushort, int> _costs = [];
    private volatile RoutingClass _preference;
    private LinkConditions _conditions = LinkConditions.Unlimited;
    private double _credit = 1400;
    private bool _dirty = true, _routesDirty = true, _stopped;
    private long _sent, _lost, _overflow, _rx, _forwarded, _invalid;
    private sealed record Edge(long Capacity, int Delay);
    private sealed record Row(long Received, Dictionary<ushort, Edge> Edges);

    public MeshRouter(ushort id, MeshMembership membership, X509Certificate2 identity, IMeshLinks links,
        TimeProvider? clock = null, int? randomSeed = null, long? generation = null)
    {
        if (!membership[id].Matches(identity) || !identity.HasPrivateKey) throw new ArgumentException("Local identity mismatch.");
        Id = id;
        Membership = membership;
        _key = identity;
        _links = links;
        _clock = clock ?? TimeProvider.System;
        _start = _clock.GetTimestamp();
        _generation = generation ?? _clock.GetUtcNow().UtcTicks;
        _random = randomSeed is int seed ? new Random(seed) : new Random();
    }

    public ushort Id { get; }
    public MeshMembership Membership { get; }
    internal ChannelReader<(ushort From, byte[] Payload)> Incoming => _received.Reader;
    public IReadOnlyDictionary<ushort, MeshRoute> Routes { get { lock (_gate) return new Dictionary<ushort, MeshRoute>(_routes); } }
    public IReadOnlyDictionary<ushort, MeshRoute> InteractiveRoutes { get { lock (_gate) return new Dictionary<ushort, MeshRoute>(_interactive); } }
    public RoutingClass Preference { get => _preference; set => _preference = value; }
    public void SetLinkCost(ushort peer, int milliseconds)
    {
        if (!Membership.Contains(peer) || milliseconds is < 0 or > 60000) throw new ArgumentOutOfRangeException(nameof(peer));
        lock (_gate) { _costs[peer] = milliseconds; _dirty = true; }
    }
    public MeshCounters Counters { get { lock (_gate) return new(_sent, _lost, _overflow, _rx, _forwarded, _invalid); } }

    public LinkConditions Conditions
    {
        get { lock (_gate) return _conditions; }
        set
        {
            ArgumentNullException.ThrowIfNull(value);
            lock (_gate)
            {
                _conditions = value;
                _credit = Math.Min(_credit, Burst);
                _dirty = true;
            }
        }
    }

    private double Burst => Math.Max(1400, _conditions.BytesPerSecond * 0.05);
    private long Now => (long)_clock.GetElapsedTime(_start).TotalMilliseconds;

    internal bool SendPayload(ushort destination, ReadOnlySpan<byte> payload)
    {
        if (payload.Length > MaxBody) throw new ArgumentOutOfRangeException(nameof(payload));
        lock (_gate)
        {
            if (_stopped || !Membership.Contains(Id) || !Membership.Contains(destination)) return false;
            if (destination == Id) return _received.Writer.TryWrite((Id, payload.ToArray()));
            bool interactive = Preference == RoutingClass.Latency;
            if (!(interactive ? _interactive : _routes).TryGetValue(destination, out var route)) return false;
            byte[] packet = new byte[6 + payload.Length];
            packet[0] = interactive ? InteractiveData : Data;
            WriteUInt16BigEndian(packet.AsSpan(1), Id);
            WriteUInt16BigEndian(packet.AsSpan(3), destination);
            packet[5] = 32;
            payload.CopyTo(packet.AsSpan(6));
            return Enqueue(_traffic, route.NextHop, packet);
        }
    }

    public void Tick()
    {
        lock (_gate)
        {
            if (_stopped) return;
            long now = Now;
            if (_policyRevision != Membership.PolicyRevision)
            {
                _policyRevision = Membership.PolicyRevision;
                foreach (var peer in _heard.Keys.Where(id => !Membership.Contains(id)).ToArray()) _heard.Remove(peer);
                foreach (var peer in _rows.Keys.Where(id => !Membership.Contains(id)).ToArray()) _rows.Remove(peer);
                _control.Clear(); _traffic.Clear();
                _dirty = _routesDirty = true;
            }
            if (!Membership.Contains(Id))
            {
                _routes.Clear(); _interactive.Clear();
                for (int i = 0; i < 2048 && _links.TryReceive(out _, out _); i++) { }
                return;
            }
            for (int i = 0; i < 2048 && _links.TryReceive(out ushort peer, out var packet); i++)
            {
                if (!Membership.Contains(peer) || peer == Id || packet.Length == 0) continue;
                _rx++;
                switch (packet[0])
                {
                    case Hello when packet.Length == 1:
                        if (!_heard.ContainsKey(peer)) _dirty = true;
                        _heard[peer] = now;
                        break;
                    case State: AcceptState(peer, packet, now); break;
                    case Data or InteractiveData: Forward(packet); break;
                    default: _invalid++; break;
                }
            }

            if (now - _lastHello >= HelloPeriod)
            {
                foreach (var peer in _links.Peers.Take(MaxNeighbors))
                    Enqueue(_control, peer, [Hello]);
                _lastHello = now;
                foreach (var peer in _heard.Where(p => now - p.Value >= DeadInterval).Select(p => p.Key).ToArray())
                {
                    _heard.Remove(peer);
                    _dirty = true;
                }
                foreach (var key in _rows.Where(p => p.Key != Id && now - p.Value.Received >= 5 * Refresh).Select(p => p.Key).ToArray())
                {
                    _rows.Remove(key);
                    _routesDirty = true;
                }
            }

            if (_dirty || now - _lastState >= Refresh) Advertise(now);
            if (_routesDirty)
            {
                _routes = Calculate(false);
                _interactive = Calculate(true);
                _routesDirty = false;
            }
            Flush(now);
        }
    }

    public void Stop(bool graceful = true)
    {
        lock (_gate)
        {
            if (_stopped) return;
            _stopped = true;
            if (graceful)
            {
                _heard.Clear();
                _control.Clear();
                _traffic.Clear();
                Advertise(Now);
                Flush(Now);
            }
            _received.Writer.TryComplete();
        }
    }

    internal async ValueTask DrainWithdrawalAsync()
    {
        long until = Environment.TickCount64 + 300;
        while (Environment.TickCount64 < until)
        {
            lock (_gate)
            {
                if (_control.Count == 0) return;
                Flush(Now);
                if (_control.Count == 0) return;
            }
            await Task.Delay(10).ConfigureAwait(false);
        }
    }

    private bool Enqueue(Queue<(ushort Peer, byte[] Packet)> queue, ushort peer, byte[] packet)
    {
        if (queue.Count >= 1024) { _overflow++; return false; }
        queue.Enqueue((peer, packet));
        return true;
    }

    private void Flush(long now)
    {
        long rate = _conditions.BytesPerSecond;
        _credit = Math.Min(Burst, _credit + (now - _lastCredit) * (double)rate / 1000);
        _lastCredit = now;
        for (int i = 0; i < 2048; i++)
        {
            var queue = _control.Count != 0 ? _control : _traffic;
            if (!queue.TryPeek(out var item)) break;
            if (rate > 0 && _credit < item.Packet.Length) break;
            queue.Dequeue();
            if (rate > 0) _credit -= item.Packet.Length;
            if (_random.NextDouble() < _conditions.Loss) { _lost++; continue; }
            ushort peer = item.Peer;
            if (queue == _traffic)
            {
                var table = item.Packet[0] == InteractiveData ? _interactive : _routes;
                ushort destination = ReadUInt16BigEndian(item.Packet.AsSpan(3));
                if (!table.TryGetValue(destination, out var route)) continue;
                peer = route.NextHop;
            }
            if (_links.Send(peer, item.Packet)) _sent += item.Packet.Length;
        }
    }

    private void Forward(byte[] packet)
    {
        if (packet.Length < 7 || packet.Length > MaxBody + 6 || packet[5] == 0) { _invalid++; return; }
        ushort source = ReadUInt16BigEndian(packet.AsSpan(1)), destination = ReadUInt16BigEndian(packet.AsSpan(3));
        if (!Membership.Contains(source)) { _invalid++; return; }
        if (destination == Id)
        {
            if (!_received.Writer.TryWrite((source, packet[6..]))) _overflow++;
        }
        else if (Membership[Id].Relay && packet[5] > 1 && (packet[0] == InteractiveData ? _interactive : _routes).TryGetValue(destination, out var route))
        {
            packet[5]--;
            if (Enqueue(_traffic, route.NextHop, packet)) _forwarded++;
        }
    }

    private void Advertise(long now)
    {
        var edges = new Dictionary<ushort, Edge>();
        foreach (var peer in _heard.Keys.Order().Take(MaxNeighbors))
        {
            long capacity = (_links as ILinkEstimates)?.Capacity(peer) ?? 0;
            if (capacity <= 0) capacity = 100_000_000;
            if (_conditions.BytesPerSecond > 0) capacity = Math.Min(capacity, _conditions.BytesPerSecond);
            int delay = Math.Clamp((_links as ILinkEstimates)?.DelayMilliseconds(peer) ?? 1, 1, 60000);
            edges[peer] = new(Math.Max(1, (long)(capacity * (1 - _conditions.Loss))), delay + _costs.GetValueOrDefault(peer));
        }
        byte[] body = new byte[20 + 14 * edges.Count];
        body[0] = State;
        WriteUInt16BigEndian(body.AsSpan(1), Id);
        WriteInt64BigEndian(body.AsSpan(3), _generation);
        WriteInt64BigEndian(body.AsSpan(11), ++_sequence);
        body[19] = (byte)edges.Count;
        int index = 20;
        foreach (var (peer, capacity) in edges)
        {
            WriteUInt16BigEndian(body.AsSpan(index), peer);
            WriteInt64BigEndian(body.AsSpan(index + 2), capacity.Capacity);
            WriteInt32BigEndian(body.AsSpan(index + 10), capacity.Delay);
            index += 14;
        }
        byte[] signed = [.. body, .. IdentityProof.Sign(_key, ProofPurpose.LinkState, body)];
        _rows[Id] = new(now, edges);
        foreach (var peer in _links.Peers.Take(MaxNeighbors)) Enqueue(_control, peer, signed);
        _lastState = now;
        _dirty = false;
        _routesDirty = true;
    }

    private void AcceptState(ushort from, byte[] packet, long now)
    {
        if (packet.Length < 21 || packet[19] > MaxNeighbors) { _invalid++; return; }
        ushort owner = ReadUInt16BigEndian(packet.AsSpan(1));
        var version = (ReadInt64BigEndian(packet.AsSpan(3)), ReadInt64BigEndian(packet.AsSpan(11)));
        if (owner == Id || !Membership.Contains(owner) || _versions.TryGetValue(owner, out var old) && version.CompareTo(old) <= 0) return;
        int end = 20 + packet[19] * 14;
        if (end >= packet.Length || !Membership[owner].Verify(ProofPurpose.LinkState, packet.AsSpan(0, end), packet.AsSpan(end))) { _invalid++; return; }
        var edges = new Dictionary<ushort, Edge>();
        for (int i = 20; i < end; i += 14)
        {
            ushort peer = ReadUInt16BigEndian(packet.AsSpan(i));
            long capacity = ReadInt64BigEndian(packet.AsSpan(i + 2));
            int delay = ReadInt32BigEndian(packet.AsSpan(i + 10));
            if (!Membership.Contains(peer) || peer == owner || capacity <= 0 || delay is < 1 or > 120000 || !edges.TryAdd(peer, new(capacity, delay))) { _invalid++; return; }
        }
        _versions[owner] = version;
        _rows[owner] = new(now, edges);
        foreach (var peer in _links.Peers.Take(MaxNeighbors))
            if (peer != from) Enqueue(_control, peer, packet);
        _routesDirty = true;
    }

    private Dictionary<ushort, MeshRoute> Calculate(bool interactive)
    {
        var paths = new Dictionary<ushort, MeshRoute> { [Id] = new(Id, 0, long.MaxValue) };
        var work = new PriorityQueue<ushort, (long Width, int Hops, ushort First, ushort Id)>();
        work.Enqueue(Id, (interactive ? 0 : -long.MaxValue, 0, Id, Id));
        while (work.TryDequeue(out ushort node, out var priority))
        {
            var path = paths[node];
            if (priority.Width != (interactive ? path.DelayMilliseconds : -path.Bottleneck) || priority.Hops != path.Hops || priority.First != path.NextHop) continue;
            if (node != Id && !Membership[node].Relay || !_rows.TryGetValue(node, out var row)) continue;
            foreach (var (peer, capacity) in row.Edges)
            {
                if (!Membership.Contains(Id) || !Membership.Contains(peer) || peer == Id || !_rows.TryGetValue(peer, out var back) || !back.Edges.ContainsKey(node)) continue;
                var candidate = new MeshRoute(node == Id ? peer : path.NextHop, path.Hops + 1, Math.Min(path.Bottleneck, capacity.Capacity), path.DelayMilliseconds + capacity.Delay);
                var rank = (interactive ? candidate.DelayMilliseconds : -candidate.Bottleneck, candidate.Hops, candidate.NextHop, peer);
                if (paths.TryGetValue(peer, out var best) && rank.CompareTo((interactive ? best.DelayMilliseconds : -best.Bottleneck, best.Hops, best.NextHop, peer)) >= 0) continue;
                paths[peer] = candidate;
                work.Enqueue(peer, rank);
            }
        }
        paths.Remove(Id);
        return paths;
    }
}
