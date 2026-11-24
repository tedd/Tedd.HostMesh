using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Channels;
using Tedd.Quicly.Core.Transport;
using Tedd.Quicly.Transport.MsQuic;

namespace Tedd.HostMesh;

/// <summary>Authenticated duplex QUIC DATAGRAM adjacencies. A null listener permits outbound connections only.</summary>
public sealed class QuiclyLinks : IMeshLinks, ILinkEstimates
{
    static QuiclyLinks()
    {
        if (OperatingSystem.IsLinux())
        {
            // Distribution packages commonly install only the ABI-versioned soname.
            var assembly = typeof(MsQuicRegistration).Assembly;
            var context = System.Runtime.Loader.AssemblyLoadContext.GetLoadContext(assembly)!;
            context.ResolvingUnmanagedDll += (requesting, name) =>
                requesting == assembly && name == "msquic" && NativeLibrary.TryLoad("libmsquic.so.2", out var handle) ? handle : IntPtr.Zero;
        }
    }

    private readonly ushort _id;
    private readonly MeshMembership _membership;
    private readonly X509Certificate2 _identity;
    private readonly MsQuicTransportListener? _listener;
    private readonly MsQuicRegistration _registration;
    private readonly Dictionary<ushort, (IPEndPoint Address, MsQuicTransportConnector Connector)> _dials = [];
    private readonly ConcurrentDictionary<Link, byte> _sessions = new();
    private readonly ConcurrentDictionary<ushort, Link> _ready = new();
    private readonly Channel<(ushort Peer, byte[] Packet)> _inbox = Channel.CreateBounded<(ushort, byte[])>(4096);
    private readonly CancellationTokenSource _stop = new();
    private readonly Task _worker;
    private readonly HashSet<ushort> _accept;
    private int _disposed;

    public QuiclyLinks(ushort id, MeshMembership membership, X509Certificate2 identity, IPEndPoint? listen,
        IReadOnlyDictionary<ushort, IPEndPoint> dial, IEnumerable<ushort>? acceptFrom = null)
    {
        _id = id;
        _membership = membership;
        _identity = identity;
        _accept = acceptFrom?.ToHashSet() ?? [];
        AcceptAllMembers = acceptFrom == null;
        if (!membership[id].Matches(identity) || !identity.HasPrivateKey) throw new ArgumentException("Local certificate mismatch.");
        _registration = new MsQuicRegistration("HostMesh");
        try
        {
            foreach (var (peer, address) in dial)
            {
                if (peer == id) throw new ArgumentException("Self dial.");
                var options = Options();
                options.ServerCertificateValidation = ServerCertificateValidationMode.PinnedSpki;
                foreach (var cert in membership[peer].Certificates)
                    options.PinnedSpkiSha256.Add(SHA256.HashData(cert.PublicKey.ExportSubjectPublicKeyInfo()));
                _dials.Add(peer, (address, new MsQuicTransportConnector(options, _registration)));
            }
            if (listen != null)
            {
                _listener = new MsQuicTransportListener(listen, identity, Options(), _registration);
                _listener.Start((in NewConnectionInfo _) => _sessions.Count < 64 ? PreHandshakeDecision.Accept : PreHandshakeDecision.Reject,
                    (ITransport transport, in NewConnectionInfo _) =>
                    {
                        var link = new Link(this, 0) { Transport = transport };
                        _sessions.TryAdd(link, 0);
                        return link;
                    });
            }
            _worker = Task.Run(RunAsync);
        }
        catch
        {
            _listener?.Dispose();
            foreach (var d in _dials.Values) d.Connector.Dispose();
            _registration.Dispose();
            throw;
        }
    }

    private bool AcceptAllMembers { get; }
    public IPEndPoint? LocalEndPoint => _listener?.LocalEndPoint;
    public IReadOnlyList<ushort> Peers => _ready.Keys.Order().ToArray();
    private static MsQuicTransportOptions Options() => new() { Alpns = ["hostmesh-hop/1"], AppName = "HostMesh", ServerPeerBidiStreamCount = 0 };

    public bool TryReceive(out ushort peer, out byte[] packet)
    {
        if (_inbox.Reader.TryRead(out var item)) { (peer, packet) = item; return true; }
        peer = 0; packet = []; return false;
    }

    public bool Send(ushort peer, ReadOnlySpan<byte> packet)
    {
        if (!_ready.TryGetValue(peer, out var link)) return false;
        return link.Send(4, packet);
    }

    public long Capacity(ushort peer) => _ready.TryGetValue(peer, out var link) ? Interlocked.Read(ref link.Estimate) : 0;

    public int DelayMilliseconds(ushort peer) => _ready.TryGetValue(peer, out var link) ? Volatile.Read(ref link.Delay) : 1;

    private async Task RunAsync()
    {
        using var timer = new PeriodicTimer(TimeSpan.FromMilliseconds(15));
        long lastDial = -1000;
        var clock = Stopwatch.StartNew();
        while (await timer.WaitForNextTickAsync(_stop.Token).ConfigureAwait(false))
        {
            long now = clock.ElapsedMilliseconds;
            foreach (var link in _sessions.Keys)
            {
                if (link.Closed || !_membership.Contains(_id) || link.Remote != 0 && !_membership.Contains(link.Remote) || link.Remote == 0 && link.Age.ElapsedMilliseconds > 5000)
                {
                    _sessions.TryRemove(link, out _);
                    if (link.Remote != 0) _ready.TryRemove(new KeyValuePair<ushort, Link>(link.Remote, link));
                    link.Transport?.Dispose();
                    continue;
                }
                while (link.Handshake.Reader.TryRead(out var bytes)) Handle(link, bytes);
                if (link.Expected == 0 && link.Remote == 0 && link.Connected && now - link.LastProof >= 200)
                {
                    link.Send(1, link.Nonce);
                    link.LastProof = now;
                }
                if (link.Expected == 0 && link.Remote != 0 && now - link.LastProof >= 700)
                {
                    link.Send(3, []);
                    link.LastProof = now;
                }
                if (link.Remote != 0 && now - link.LastSample >= 1000)
                {
                    link.LastSample = now;
                    link.Transport!.GetStatistics(out var stats);
                    if (stats.RttMicros > 0 && stats.CongestionWindowBytes > 0)
                    {
                        long rate = (long)stats.CongestionWindowBytes * 1_000_000 / stats.RttMicros;
                        long delivered = Interlocked.Read(ref link.AcknowledgedBytes);
                        long interval = Math.Max(1, now - link.SampleStarted);
                        long goodput = (delivered - link.PreviousBytes) * 1000 / interval;
                        link.SampleStarted = now;
                        link.PreviousBytes = delivered;
                        // Idle traffic supplies no capacity measurement. Sample useful bytes during loaded intervals.
                        if (Interlocked.Exchange(ref link.Loaded, 0) != 0 && goodput > 0)
                            rate = Math.Min(rate, goodput);
                        long previous = link.Estimate;
                        link.Smoothed = link.Smoothed == 0 ? rate : (7 * link.Smoothed + rate) / 8;
                        // Publish material changes after three consecutive observations in the same direction.
                        int trend = previous == 0 ? 0 : link.Smoothed > previous * 1.15 ? 1 : link.Smoothed < previous * 0.85 ? -1 : 0;
                        link.TrendCount = trend == link.Trend ? link.TrendCount + 1 : 1;
                        link.Trend = trend;
                        if (previous == 0 || trend != 0 && link.TrendCount >= 3)
                            Interlocked.Exchange(ref link.Estimate, link.Smoothed);
                        Volatile.Write(ref link.Delay, Math.Max(1, (int)(stats.RttMicros / 1000)));
                    }
                }
            }
            if (now - lastDial < 500) continue;
            lastDial = now;
            foreach (var (peer, dial) in _dials)
            {
                if (!_membership.Contains(_id) || !_membership.Contains(peer) || _ready.ContainsKey(peer) || _sessions.Keys.Any(s => s.Expected == peer && !s.Closed)) continue;
                var link = new Link(this, peer);
                try
                {
                    link.Transport = dial.Connector.Connect(dial.Address, "hostmesh", link);
                    _sessions.TryAdd(link, 0);
                }
                catch (Exception ex) when (ex is not OutOfMemoryException) { link.Transport?.Dispose(); }
            }
        }
    }

    private static byte[] Transcript(ushort client, ushort server, ReadOnlySpan<byte> nonce)
    {
        byte[] bytes = new byte[4 + nonce.Length];
        BinaryPrimitives.WriteUInt16BigEndian(bytes, client);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(2), server);
        nonce.CopyTo(bytes.AsSpan(4));
        return bytes;
    }

    private void Handle(Link link, byte[] bytes)
    {
        if (bytes.Length < 3) return;
        ushort remote = BinaryPrimitives.ReadUInt16BigEndian(bytes.AsSpan(1));
        if (remote == _id || !_membership.Contains(remote) || link.Remote != 0 && link.Remote != remote) return;
        if (link.Expected != 0 && remote != link.Expected) return;
        if (link.Expected == 0 && !AcceptAllMembers && !_accept.Contains(remote)) return;
        switch (bytes[0])
        {
            case 1 when link.Expected != 0 && bytes.Length == 35:
                link.Send(2, IdentityProof.Sign(_identity, ProofPurpose.PeerAdmission, Transcript(_id, remote, bytes.AsSpan(3))));
                break;
            case 2 when link.Expected == 0:
                if (!_membership[remote].Verify(ProofPurpose.PeerAdmission, Transcript(remote, _id, link.Nonce), bytes.AsSpan(3))) return;
                Publish(link, remote);
                link.Send(3, []);
                break;
            case 3 when link.Expected != 0:
                Publish(link, remote);
                break;
        }
    }

    private void Publish(Link link, ushort remote)
    {
        link.Remote = remote;
        _ready.AddOrUpdate(remote, link, (_, old) =>
            old.Closed || ((link.Expected != 0) == (_id < remote)) ? link : old);
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        _stop.Cancel();
        try { await _worker.ConfigureAwait(false); } catch (OperationCanceledException) { }
        _listener?.Stop();
        long until = Environment.TickCount64 + 250;
        while (_sessions.Keys.Any(s => s.HasOutstanding) && Environment.TickCount64 < until)
            await Task.Delay(10).ConfigureAwait(false);
        foreach (var link in _sessions.Keys) link.Transport?.Dispose();
        _listener?.Dispose();
        foreach (var dial in _dials.Values) dial.Connector.Dispose();
        _registration.Dispose();
        _ready.Clear();
        _inbox.Writer.TryComplete();
        _stop.Dispose();
    }

    private sealed class Link(QuiclyLinks owner, ushort expected) : ITransportSink
    {
        internal readonly ushort Expected = expected;
        internal volatile ushort Remote;
        internal volatile bool Connected, Closed;
        internal volatile ITransport? Transport;
        internal readonly Stopwatch Age = Stopwatch.StartNew();
        internal readonly byte[] Nonce = RandomNumberGenerator.GetBytes(32);
        internal readonly Channel<byte[]> Handshake = Channel.CreateBounded<byte[]>(32);
        internal long LastProof = -500, LastSample, Estimate, Smoothed, AcknowledgedBytes, PreviousBytes, SampleStarted;
        internal int Trend, TrendCount, Loaded, Delay = 1;
        private int _inFlight;
        internal bool HasOutstanding => Volatile.Read(ref _inFlight) != 0;

        internal unsafe bool Send(byte kind, ReadOnlySpan<byte> data)
        {
            var transport = Transport;
            if (Closed || !Connected || transport == null || data.Length > 1100) return false;
            int outstanding = Interlocked.Increment(ref _inFlight);
            if (outstanding >= 32) Volatile.Write(ref Loaded, 1);
            if (outstanding > 512) { Interlocked.Decrement(ref _inFlight); return false; }
            int header = kind == 4 ? 1 : 3;
            int length = header + data.Length;
            var segment = (TransportSegment*)NativeMemory.Alloc((nuint)(sizeof(TransportSegment) + length));
            byte* body = (byte*)(segment + 1);
            *segment = new TransportSegment(body, length);
            body[0] = kind;
            if (header == 3) BinaryPrimitives.WriteUInt16BigEndian(new Span<byte>(body + 1, 2), owner._id);
            data.CopyTo(new Span<byte>(body + header, data.Length));
            if (transport.SendDatagram(segment, 1, (ulong)segment, 0) == TransportStatus.Success) return true;
            NativeMemory.Free(segment);
            Interlocked.Decrement(ref _inFlight);
            return false;
        }

        public void OnDatagramReceived(ReadOnlySpan<byte> payload)
        {
            if (payload.IsEmpty || payload.Length > 1103) return;
            if (payload[0] == 4)
            {
                if (Remote != 0) owner._inbox.Writer.TryWrite((Remote, payload[1..].ToArray()));
            }
            else Handshake.Writer.TryWrite(payload.ToArray());
        }
        public unsafe void OnDatagramSendStateChanged(ulong context, DatagramSendState state)
        {
            if (!state.IsFinal()) return;
            if (state is DatagramSendState.Acknowledged or DatagramSendState.AcknowledgedSpurious)
                Interlocked.Add(ref AcknowledgedBytes, ((TransportSegment*)context)->Length);
            NativeMemory.Free((void*)context);
            Interlocked.Decrement(ref _inFlight);
        }
        public void OnConnected(in TransportConnectedInfo info) => Connected = true;
        public void OnClosed(TransportCloseReason reason, ulong errorCode, int transportStatus) => Closed = true;
        public void OnPeerStreamStarted(TransportStreamId id, StreamKind kind) { }
        public void OnStreamStarted(TransportStreamId id, ulong context, TransportStatus status) { }
        public ReceiveResult OnStreamReceived(TransportStreamId id, ReadOnlySpan<TransportSegment> segments, ulong absoluteOffset, bool fin) => ReceiveResult.Consumed(0);
        public void OnStreamSendCompleted(TransportStreamId id, ulong context, bool canceled) { }
        public void OnStreamAborted(TransportStreamId id, ulong errorCode, StreamAbortDirection direction) { }
        public void OnStreamPeerSendShutdown(TransportStreamId id) { }
        public void OnStreamShutdownComplete(TransportStreamId id) => Transport?.CloseStream(id);
        public void OnDatagramCapabilityChanged(bool enabled, int maxPayload) { }
        public void OnIdealSendBufferSize(TransportStreamId id, ulong bytes) { }
        public void OnStreamsAvailable(ushort bidirectional, ushort unidirectional) { }
        public void OnPeerAddressChanged(in TransportConnectedInfo info) { }
    }
}
