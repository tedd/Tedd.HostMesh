using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;

namespace Tedd.HostMesh;

/// <summary>Owns a physical listener and its live forwards. Disposing it cancels and drains all workers.</summary>
public sealed class SocketForward : IAsyncDisposable
{
    private readonly CancellationTokenSource _stop = new();
    private readonly ConcurrentDictionary<Task, byte> _workers = new();
    private readonly Task _loop;
    private readonly Action _close;
    private int _disposed;

    internal SocketForward(Func<SocketForward, CancellationToken, Task> run, Action close, EndPoint? bound = null)
    {
        _close = close;
        LocalEndPoint = bound;
        _loop = Task.Run(() => run(this, _stop.Token));
    }
    public EndPoint? LocalEndPoint { get; }
    internal bool HasCapacity => _workers.Count < 256;
    internal void Run(Task work)
    {
        _workers.TryAdd(work, 0);
        _ = work.ContinueWith(t => { _ = t.Exception; _workers.TryRemove(t, out _); }, CancellationToken.None,
            TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        _stop.Cancel(); _close();
        try { await _loop; }
        catch (Exception ex) when (ex is IOException or OperationCanceledException or ObjectDisposedException or SocketException or System.Threading.Channels.ChannelClosedException) { }
        while (!_workers.IsEmpty) { try { await Task.WhenAll(_workers.Keys); } catch (Exception) { } }
        _stop.Dispose();
    }
}

public static class SocketForwards
{
    public static SocketForward ListenTcp(this MeshApplication app, IPEndPoint physical, IPEndPoint destination,
        params System.Net.IPNetwork[] allowedClients)
    {
        app.AuthorizeIngress(destination);
        var listener = new TcpListener(physical);
        listener.Start(128);
        return new SocketForward(async (owner, ct) =>
        {
            while (!ct.IsCancellationRequested)
            {
                var socket = await listener.AcceptSocketAsync(ct);
                var remote = (IPEndPoint)socket.RemoteEndPoint!;
                if (!owner.HasCapacity || !allowedClients.Any(rule => rule.Contains(remote.Address))) { socket.Dispose(); continue; }
                owner.Run(Serve(socket, remote, ct));
            }
        }, listener.Stop, listener.LocalEndpoint);

        async Task Serve(Socket socket, IPEndPoint remote, CancellationToken ct)
        {
            using (socket)
            {
                await using var flow = await app.ConnectFromAsync(destination, remote, ct);
                await CopyDuplex(socket, flow, ct);
            }
        }
    }

    public static MeshListener ForwardTcp(this MeshApplication app, int meshPort, IPEndPoint target,
        params System.Net.IPNetwork[] allowedSources) =>
        app.ListenTarget(meshPort, target, allowedSources);

    /// <summary>For targets explicitly configured to accept a PROXY protocol v2 preamble before application data.</summary>
    public static MeshListener ForwardProxyTcp(this MeshApplication app, int meshPort, IPEndPoint target,
        params System.Net.IPNetwork[] allowedSources) => app.ListenTarget(meshPort, target, allowedSources, true);

    internal static byte[] ProxyHeader(IPEndPoint source, IPEndPoint destination)
    {
        bool ipv6 = source.AddressFamily == AddressFamily.InterNetworkV6 || destination.AddressFamily == AddressFamily.InterNetworkV6;
        var from = ipv6 ? source.Address.MapToIPv6() : source.Address;
        var to = ipv6 ? destination.Address.MapToIPv6() : destination.Address;
        int addressLength = ipv6 ? 16 : 4;
        var bytes = new byte[20 + 2 * addressLength];
        new byte[] { 13, 10, 13, 10, 0, 13, 10, 81, 85, 73, 84, 10, 0x21 }.CopyTo(bytes, 0);
        bytes[13] = ipv6 ? (byte)0x21 : (byte)0x11;
        System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(14), (ushort)(bytes.Length - 16));
        from.TryWriteBytes(bytes.AsSpan(16, addressLength), out _);
        to.TryWriteBytes(bytes.AsSpan(16 + addressLength, addressLength), out _);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(bytes.Length - 4), (ushort)source.Port);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(bytes.Length - 2), (ushort)destination.Port);
        return bytes;
    }

    internal static async Task CopyDuplex(Socket socket, MeshConnection flow, CancellationToken ct)
    {
        using var abort = CancellationTokenSource.CreateLinkedTokenSource(ct);
        using var local = new NetworkStream(socket, false);
        int failed = 0;
        async Task Copy(Stream from, Stream to, Action finish)
        {
            try { await from.CopyToAsync(to, 32768, abort.Token); finish(); }
            catch
            {
                if (Interlocked.Exchange(ref failed, 1) == 0)
                {
                    abort.Cancel();
                    try { flow.Abort(); } catch (Exception ex) when (ex is IOException or ObjectDisposedException) { }
                    if (socket.AddressFamily is AddressFamily.InterNetwork or AddressFamily.InterNetworkV6)
                        try { socket.LingerState = new LingerOption(true, 0); } catch (Exception ex) when (ex is SocketException or ObjectDisposedException) { }
                }
                throw;
            }
        }
        await Task.WhenAll(Copy(local, flow.Stream, flow.CompleteWrites),
            Copy(flow.Stream, local, () => socket.Shutdown(SocketShutdown.Send)));
    }

    internal static async Task ServeTarget(Socket socket, MeshConnection connection, CancellationToken token)
    {
        using (socket)
        await using (connection)
            await CopyDuplex(socket, connection, token);
    }

    public static SocketForward ListenUdp(this MeshApplication app, IPEndPoint physical, IPEndPoint target,
        params System.Net.IPNetwork[] allowedClients)
    {
        app.AuthorizeIngress(target);
        var udp = new UdpClient(physical);
        var associations = new ConcurrentDictionary<IPEndPoint, UdpAssociation<MeshDatagramSocket>>();
        return new SocketForward(async (owner, ct) =>
        {
            while (!ct.IsCancellationRequested)
            {
                var packet = await udp.ReceiveAsync(ct);
                if (!allowedClients.Any(r => r.Contains(packet.RemoteEndPoint.Address)) || packet.Buffer.Length > 60_000) continue;
                if (!associations.TryGetValue(packet.RemoteEndPoint, out var binding))
                {
                    if (!owner.HasCapacity) continue;
                    binding = new(app.BindEphemeral(HostRule(target.Address)), ct);
                    if (!associations.TryAdd(packet.RemoteEndPoint, binding)) { binding.Dispose(); continue; }
                    owner.Run(ReturnPackets(packet.RemoteEndPoint, binding, ct));
                }
                try { binding.Touch(); binding.Socket.SendFrom(target, packet.Buffer, packet.RemoteEndPoint); } catch (ObjectDisposedException) { }
            }
        }, udp.Dispose, udp.Client.LocalEndPoint);

        async Task ReturnPackets(IPEndPoint client, UdpAssociation<MeshDatagramSocket> binding, CancellationToken ct)
        {
            using (binding)
            {
                try
                {
                    while (!ct.IsCancellationRequested)
                    {
                        var packet = await binding.Socket.ReceiveAsync(binding.Token);
                        binding.Touch();
                        if (packet.Source.Equals(target)) await udp.SendAsync(packet.Payload, client, ct);
                    }
                }
                finally { associations.TryRemove(new KeyValuePair<IPEndPoint, UdpAssociation<MeshDatagramSocket>>(client, binding)); }
            }
        }
    }

    public static SocketForward ForwardUdp(this MeshApplication app, int meshPort, IPEndPoint target,
        params System.Net.IPNetwork[] allowedSources)
    {
        var binding = app.BindDatagram(meshPort, allowedSources);
        var associations = new ConcurrentDictionary<IPEndPoint, UdpAssociation<UdpClient>>();
        return new SocketForward(async (owner, ct) =>
        {
            while (!ct.IsCancellationRequested)
            {
                var packet = await binding.ReceiveAsync(ct);
                if (!associations.TryGetValue(packet.Source, out var socket))
                {
                    if (!owner.HasCapacity) continue;
                    socket = new(new UdpClient(target.AddressFamily), ct);
                    socket.Socket.Connect(target);
                    associations[packet.Source] = socket;
                    owner.Run(ReturnPackets(packet.Source, socket, ct));
                }
                try { socket.Touch(); await socket.Socket.SendAsync(packet.Payload, ct); } catch (ObjectDisposedException) { }
            }
        }, binding.Dispose);

        async Task ReturnPackets(IPEndPoint source, UdpAssociation<UdpClient> socket, CancellationToken ct)
        {
            using (socket)
            {
                try
                {
                    while (!ct.IsCancellationRequested)
                    {
                        var reply = await socket.Socket.ReceiveAsync(socket.Token);
                        socket.Touch();
                        if (reply.Buffer.Length <= 60_000) binding.SendTo(source, reply.Buffer);
                    }
                }
                finally { associations.TryRemove(new KeyValuePair<IPEndPoint, UdpAssociation<UdpClient>>(source, socket)); }
            }
        }
    }

    private sealed class UdpAssociation<T> : IDisposable where T : IDisposable
    {
        private readonly CancellationTokenSource _idle;
        internal T Socket { get; }
        internal CancellationToken Token => _idle.Token;
        internal UdpAssociation(T socket, CancellationToken stop)
        {
            Socket = socket;
            _idle = CancellationTokenSource.CreateLinkedTokenSource(stop);
            Touch();
        }
        internal void Touch() => _idle.CancelAfter(TimeSpan.FromMinutes(2));
        public void Dispose() { Socket.Dispose(); _idle.Dispose(); }
    }

    internal static System.Net.IPNetwork HostRule(IPAddress ip) => new(ip, ip.GetAddressBytes().Length * 8);
}
