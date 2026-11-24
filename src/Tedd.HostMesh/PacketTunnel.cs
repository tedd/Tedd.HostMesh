using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using static System.Buffers.Binary.BinaryPrimitives;

namespace Tedd.HostMesh;

internal readonly record struct PacketKey(ushort Remote, byte Kind, ulong Tunnel, uint Sequence);

internal sealed class FragmentTable
{
    internal const int Header = 16, Chunk = MeshRouter.MaxBody - Header;
    private sealed class Assembly(int length, long now)
    {
        public readonly byte[] Buffer = new byte[length];
        public readonly bool[] Seen = new bool[(length + Chunk - 1) / Chunk];
        public readonly long Created = now;
        public int Count;
    }

    private readonly Dictionary<PacketKey, Assembly> _assemblies = [];
    internal int Count => _assemblies.Count;

    public static byte[] Encode(byte kind, ulong tunnel, uint sequence, ReadOnlySpan<byte> bytes, int index)
    {
        int offset = index * Chunk;
        var slice = bytes.Slice(offset, Math.Min(Chunk, bytes.Length - offset));
        byte[] frame = new byte[Header + slice.Length];
        frame[0] = kind;
        WriteUInt64BigEndian(frame.AsSpan(1), tunnel);
        WriteUInt32BigEndian(frame.AsSpan(9), sequence);
        WriteUInt16BigEndian(frame.AsSpan(13), checked((ushort)bytes.Length));
        frame[15] = checked((byte)index);
        slice.CopyTo(frame.AsSpan(Header));
        return frame;
    }

    public byte[]? Add(ushort from, byte[] frame, long now, out PacketKey key)
    {
        key = default;
        if (frame.Length <= Header || frame[0] is < 1 or > 3) return null;
        int length = ReadUInt16BigEndian(frame.AsSpan(13)), index = frame[15], offset = index * Chunk;
        if (length is 0 or > 65507 || offset >= length || frame.Length - Header != Math.Min(Chunk, length - offset)) return null;
        key = new(from, frame[0], ReadUInt64BigEndian(frame.AsSpan(1)), ReadUInt32BigEndian(frame.AsSpan(9)));
        if (length <= Chunk) return frame[Header..];
        if (!_assemblies.TryGetValue(key, out var entry))
        {
            if (_assemblies.Count >= 256) return null;
            _assemblies.Add(key, entry = new(length, now));
        }
        if (entry.Buffer.Length != length || entry.Seen[index]) return null;
        frame.AsSpan(Header).CopyTo(entry.Buffer.AsSpan(offset));
        entry.Seen[index] = true;
        if (++entry.Count != entry.Seen.Length) return null;
        _assemblies.Remove(key);
        return entry.Buffer;
    }

    public void Expire(long now)
    {
        foreach (var pair in _assemblies.Where(x => now - x.Value.Created >= 3000).ToArray()) _assemblies.Remove(pair.Key);
    }
}

/// <summary>Stable loopback UDP endpoints carry end-to-end QUIC packets through a changing overlay route.</summary>
internal sealed class PacketTunnel : IAsyncDisposable
{
    private readonly MeshRouter _router;
    private readonly IPEndPoint _listener;
    private readonly CancellationTokenSource _stop = new();
    private readonly ConcurrentDictionary<(ushort Remote, ulong Id, bool Outbound), Port> _ports = new();
    private readonly FragmentTable _fragments = new();
    private readonly Task _reader, _sweeper;
    private readonly Action<ushort, byte[]> _native;
    private readonly TimeSpan _idle;
    private int _sequence;

    internal PacketTunnel(MeshRouter router, IPEndPoint listener, TimeSpan idle, Action<ushort, byte[]> native)
    {
        _router = router;
        _listener = listener;
        _idle = idle + TimeSpan.FromSeconds(5);
        _native = native;
        _reader = Task.Run(ReadAsync);
        _sweeper = Task.Run(SweepAsync);
    }

    internal (IPEndPoint Local, Action Release) Open(ushort remote)
    {
        ulong id = ReadUInt64BigEndian(RandomNumberGenerator.GetBytes(8));
        var port = Create(remote, id, true) ?? throw new IOException("Tunnel limit reached.");
        return ((IPEndPoint)port.Udp.LocalEndPoint!, () => Remove(port));
    }

    internal bool Send(ushort remote, byte kind, ulong id, ReadOnlySpan<byte> data)
    {
        if (data.Length is 0 or > 65507) return false;
        var sequence = unchecked((uint)Interlocked.Increment(ref _sequence));
        for (int i = 0; i * FragmentTable.Chunk < data.Length; i++)
            if (!_router.SendPayload(remote, FragmentTable.Encode(kind, id, sequence, data, i))) return false;
        return true;
    }

    private sealed class Port(ushort remote, ulong id, bool outbound)
    {
        internal readonly (ushort Remote, ulong Id, bool Outbound) Key = (remote, id, outbound);
        internal readonly Socket Udp = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        internal volatile EndPoint? LocalPeer;
        internal long Last = Environment.TickCount64;
        internal Task Pump = Task.CompletedTask;
    }

    private Port? Create(ushort remote, ulong id, bool outbound)
    {
        lock (_ports)
        {
            if (_ports.TryGetValue((remote, id, outbound), out var existing)) return existing;
            if (_ports.Count >= 256 || _stop.IsCancellationRequested) return null;
            var port = new Port(remote, id, outbound);
            port.Udp.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            if (!outbound) port.LocalPeer = _listener;
            _ports[port.Key] = port;
            port.Pump = PumpAsync(port);
            return port;
        }
    }

    private void Remove(Port port)
    {
        if (_ports.TryRemove(new KeyValuePair<(ushort, ulong, bool), Port>(port.Key, port))) port.Udp.Dispose();
    }

    private async Task PumpAsync(Port port)
    {
        byte[] buffer = new byte[65535];
        var any = new IPEndPoint(IPAddress.Loopback, 0);
        try
        {
            while (!_stop.IsCancellationRequested)
            {
                var result = await port.Udp.ReceiveFromAsync(buffer, SocketFlags.None, any, _stop.Token);
                if (port.LocalPeer != null && !port.LocalPeer.Equals(result.RemoteEndPoint)) continue;
                port.LocalPeer ??= result.RemoteEndPoint;
                Interlocked.Exchange(ref port.Last, Environment.TickCount64);
                Send(port.Key.Remote, port.Key.Outbound ? (byte)1 : (byte)2, port.Key.Id, buffer.AsSpan(0, result.ReceivedBytes));
            }
        }
        catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException or SocketException) { }
    }

    private async Task ReadAsync()
    {
        try
        {
            await foreach (var (from, frame) in _router.Incoming.ReadAllAsync(_stop.Token))
            {
                byte[]? bytes;
                PacketKey key;
                lock (_fragments) bytes = _fragments.Add(from, frame, Environment.TickCount64, out key);
                if (bytes == null) continue;
                if (key.Kind == 3) { _native(from, bytes); continue; }
                bool outbound = key.Kind == 2;
                if (!_ports.TryGetValue((from, key.Tunnel, outbound), out var port))
                {
                    // Only a long-header QUIC packet can establish a remote mapping.
                    if (outbound || bytes.Length < 1200 || (bytes[0] & 0xc0) != 0xc0) continue;
                    port = Create(from, key.Tunnel, false);
                }
                if (port?.LocalPeer is not { } target) continue;
                Interlocked.Exchange(ref port.Last, Environment.TickCount64);
                try { await port.Udp.SendToAsync(bytes, SocketFlags.None, target, _stop.Token); }
                catch (Exception ex) when (ex is ObjectDisposedException or SocketException) { }
            }
        }
        catch (OperationCanceledException) when (_stop.IsCancellationRequested) { }
    }

    private async Task SweepAsync()
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(1));
        try
        {
            while (await timer.WaitForNextTickAsync(_stop.Token))
            {
                long now = Environment.TickCount64;
                lock (_fragments) _fragments.Expire(now);
                foreach (var port in _ports.Values)
                    if (now - Interlocked.Read(ref port.Last) > _idle.TotalMilliseconds) Remove(port);
            }
        }
        catch (OperationCanceledException) when (_stop.IsCancellationRequested) { }
    }

    public async ValueTask DisposeAsync()
    {
        _stop.Cancel();
        await Task.WhenAll(_reader, _sweeper);
        var ports = _ports.Values.ToArray();
        foreach (var port in ports) Remove(port);
        await Task.WhenAll(ports.Select(p => p.Pump));
        _stop.Dispose();
    }
}
