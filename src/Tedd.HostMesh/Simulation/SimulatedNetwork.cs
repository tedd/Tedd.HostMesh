using System.Collections.Concurrent;

namespace Tedd.HostMesh.Simulation;

public sealed record SimulatedLink(LinkConditions Conditions, int DelayMilliseconds = 0, int JitterMilliseconds = 0, double Duplicate = 0)
{
    internal void Validate()
    {
        ArgumentNullException.ThrowIfNull(Conditions);
        if (DelayMilliseconds < 0 || JitterMilliseconds is < 0 or > 60_000 || !double.IsFinite(Duplicate) || Duplicate is < 0 or > 1)
            throw new ArgumentOutOfRangeException(nameof(SimulatedLink));
    }
}

public sealed class SimulationClock : TimeProvider
{
    private long _milliseconds;
    public override long TimestampFrequency => 1000;
    public override long GetTimestamp() => Interlocked.Read(ref _milliseconds);
    public override DateTimeOffset GetUtcNow() => DateTimeOffset.UnixEpoch.AddMilliseconds(GetTimestamp());
    public void Advance(int milliseconds)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(milliseconds);
        Interlocked.Add(ref _milliseconds, milliseconds);
    }
}

/// <summary>A seeded physical network. Dial permissions establish duplex links. Impairments are directional.</summary>
public sealed class SimulatedNetwork
{
    private readonly object _gate = new();
    private readonly Random _random;
    private readonly TimeProvider _clock;
    private readonly long _start;
    private readonly Dictionary<ushort, Port> _ports = [];
    private readonly HashSet<(ushort From, ushort To)> _dials = [];
    private readonly Dictionary<(ushort, ushort), SimulatedLink> _profiles = [];
    private readonly Dictionary<(ushort, ushort), double> _freeAt = [];
    private readonly PriorityQueue<(Port Source, Port Target, byte[] Packet), (double Time, long Order)> _pending = new();
    private long _order;
    private static readonly SimulatedLink DefaultLink = new(LinkConditions.Unlimited);

    public SimulatedNetwork(int seed, TimeProvider? clock = null)
    {
        _random = new(seed);
        _clock = clock ?? TimeProvider.System;
        _start = _clock.GetTimestamp();
    }

    public IMeshLinks Attach(ushort node)
    {
        lock (_gate)
        {
            if (_ports.TryGetValue(node, out var existing) && existing.Alive) throw new InvalidOperationException("Node is already running.");
            var port = new Port(this, node);
            _ports[node] = port;
            return port;
        }
    }

    public void AllowDial(ushort from, ushort to, bool allowed = true)
    {
        if (from == to) throw new ArgumentException("A node cannot dial itself.");
        lock (_gate)
        {
            if (allowed) _dials.Add((from, to));
            else _dials.Remove((from, to));
        }
    }

    public void Configure(ushort from, ushort to, SimulatedLink profile)
    {
        profile.Validate();
        lock (_gate) _profiles[(from, to)] = profile;
    }

    public void Kill(ushort node)
    {
        lock (_gate)
        {
            // Leave the peer visible. Neighbors discover silence through their own failure detectors.
            _ports[node].Alive = false;
        }
    }

    private bool Connected(ushort a, ushort b) => _dials.Contains((a, b)) || _dials.Contains((b, a));
    private double Now => _clock.GetElapsedTime(_start).TotalMilliseconds;

    private bool Send(Port source, ushort peer, ReadOnlySpan<byte> packet)
    {
        lock (_gate)
        {
            if (!source.Alive || !Connected(source.Id, peer) || !_ports.TryGetValue(peer, out var target)) return false;
            var key = (source.Id, peer);
            var profile = _profiles.GetValueOrDefault(key, DefaultLink);
            if (!target.Alive || _random.NextDouble() < profile.Conditions.Loss || _pending.Count >= 32768) return true;
            var start = Math.Max(Now, _freeAt.GetValueOrDefault(key));
            double finish = start + (profile.Conditions.BytesPerSecond == 0 ? 0 : packet.Length * 1000d / profile.Conditions.BytesPerSecond);
            _freeAt[key] = finish;
            var copy = packet.ToArray();
            var due = finish + profile.DelayMilliseconds + _random.Next(profile.JitterMilliseconds + 1);
            _pending.Enqueue((source, target, copy), (due, ++_order));
            if (_random.NextDouble() < profile.Duplicate)
                _pending.Enqueue((source, target, copy.ToArray()), (due + 1, ++_order));
            return true;
        }
    }

    private void Deliver()
    {
        double now = Now;
        while (_pending.TryPeek(out var item, out var time) && time.Time <= now)
        {
            _pending.Dequeue();
            if (item.Target.Alive && item.Target.Inbox.Count < 2048 && Connected(item.Source.Id, item.Target.Id))
                item.Target.Inbox.Enqueue((item.Source.Id, item.Packet));
        }
    }

    private sealed class Port(SimulatedNetwork network, ushort id) : IMeshLinks, ILinkEstimates
    {
        internal ushort Id { get; } = id;
        internal bool Alive = true;
        internal readonly Queue<(ushort From, byte[] Packet)> Inbox = new();

        public IReadOnlyList<ushort> Peers
        {
            get { lock (network._gate) return network._ports.Keys.Where(n => network.Connected(Id, n)).Order().ToArray(); }
        }

        public long Capacity(ushort peer)
        {
            lock (network._gate) return network._profiles.GetValueOrDefault((Id, peer), DefaultLink).Conditions.BytesPerSecond;
        }

        public int DelayMilliseconds(ushort peer)
        {
            lock (network._gate) return Math.Max(1, network._profiles.GetValueOrDefault((Id, peer), DefaultLink).DelayMilliseconds);
        }
        public bool Send(ushort peer, ReadOnlySpan<byte> packet) => network.Send(this, peer, packet);
        public bool TryReceive(out ushort peer, out byte[] packet)
        {
            lock (network._gate)
            {
                network.Deliver();
                if (Alive && Inbox.TryDequeue(out var item)) { (peer, packet) = item; return true; }
                peer = 0;
                packet = [];
                return false;
            }
        }

        public ValueTask DisposeAsync()
        {
            lock (network._gate)
            {
                Alive = false;
                if (ReferenceEquals(network._ports.GetValueOrDefault(Id), this)) network._ports.Remove(Id);
            }
            return ValueTask.CompletedTask;
        }
    }
}
