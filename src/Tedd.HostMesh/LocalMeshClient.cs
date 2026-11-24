using System.Net;
using System.Net.Sockets;
using static System.Buffers.Binary.BinaryPrimitives;

namespace Tedd.HostMesh;

/// <summary>A local application credential selects one configured mesh address and its permissions.</summary>
public sealed class LocalMeshClient
{
    private readonly UnixDomainSocketEndPoint _agent;
    private readonly byte[] _key;
    public LocalMeshClient(string socketPath, ReadOnlySpan<byte> key)
    {
        if (key.Length != 32) throw new ArgumentException("An application key must be 32 bytes.");
        _agent = new(socketPath);
        _key = key.ToArray();
    }

    public SocketsHttpHandler CreateHttpHandler(Func<string, IPAddress>? resolve = null) => new()
    {
        UseProxy = false,
        ConnectCallback = async (context, token) =>
        {
            var name = context.DnsEndPoint.Host;
            var ip = IPAddress.TryParse(name, out var literal) ? literal :
                resolve?.Invoke(name) ?? throw new IOException("Supply a mesh address resolver for host names.");
            var connection = await ConnectAsync(new(ip, context.DnsEndPoint.Port), token).ConfigureAwait(false);
            return connection.Stream;
        }
    };

    private async Task<Socket> Open(byte operation, IPEndPoint endpoint, CancellationToken token)
    {
        var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        try
        {
            await socket.ConnectAsync(_agent, token);
            using var stream = new NetworkStream(socket, false);
            byte[] header = new byte[53];
            header[0] = 1;
            _key.CopyTo(header, 1);
            header[33] = operation;
            EndpointCodec.Write(header.AsSpan(34), endpoint);
            await stream.WriteAsync(header, token);
            var ack = new byte[1];
            await stream.ReadExactlyAsync(ack, token);
            if (ack[0] != 1) throw new IOException("Local mesh request refused.");
            return socket;
        }
        catch { socket.Dispose(); throw; }
    }

    public async Task<LocalMeshConnection> ConnectAsync(IPEndPoint destination, CancellationToken cancellationToken = default) =>
        await OpenConnection(1, destination, cancellationToken);

    internal async Task<LocalMeshConnection> OpenConnection(byte operation, IPEndPoint endpoint, CancellationToken token)
    {
        var socket = await Open(operation, endpoint, token);
        try
        {
            using var stream = new NetworkStream(socket, false);
            byte[] header = new byte[59];
            await stream.ReadExactlyAsync(header, token);
            var remote = new PeerContext(EndpointCodec.Read(header.AsSpan(19)),
                header[38] == 0 ? null : EndpointCodec.Read(header.AsSpan(38)), ReadUInt16BigEndian(header.AsSpan(57)));
            return new(socket, EndpointCodec.Read(header), remote);
        }
        catch { socket.Dispose(); throw; }
    }

    public async Task<LocalMeshListener> ListenAsync(int port, CancellationToken cancellationToken = default)
    {
        var address = new IPEndPoint(IPAddress.Any, port);
        return new(this, await Open(2, address, cancellationToken), address);
    }

    public async Task<LocalDatagramSocket> BindDatagramAsync(int port, CancellationToken cancellationToken = default) =>
        new(await Open(4, new(IPAddress.Any, port), cancellationToken));
}

public sealed class LocalMeshListener : IDisposable
{
    private readonly LocalMeshClient _client;
    private readonly Socket _registration;
    private readonly IPEndPoint _endpoint;
    internal LocalMeshListener(LocalMeshClient client, Socket socket, IPEndPoint endpoint) =>
        (_client, _registration, _endpoint) = (client, socket, endpoint);
    public Task<LocalMeshConnection> AcceptAsync(CancellationToken token = default) => _client.OpenConnection(3, _endpoint, token);
    public void Dispose() => _registration.Dispose();
}

public sealed class LocalMeshConnection : IDisposable
{
    private readonly Socket _socket;
    internal LocalMeshConnection(Socket socket, IPEndPoint local, PeerContext peer)
    {
        _socket = socket; Stream = new NetworkStream(socket, true); LocalEndPoint = local; Peer = peer;
    }
    public Stream Stream { get; }
    public PeerContext Peer { get; }
    public IPEndPoint LocalEndPoint { get; }
    public void CompleteWrites() => _socket.Shutdown(SocketShutdown.Send);
    public void Dispose() => Stream.Dispose();
}

public sealed class LocalDatagramSocket : IDisposable
{
    private readonly NetworkStream _stream;
    private readonly SemaphoreSlim _send = new(1), _receive = new(1);
    internal LocalDatagramSocket(Socket socket) => _stream = new NetworkStream(socket, true);
    public async ValueTask SendToAsync(IPEndPoint destination, ReadOnlyMemory<byte> payload, CancellationToken token = default)
    {
        await _send.WaitAsync(token);
        try { await LocalDatagramProtocol.Write(_stream, destination, payload, token); }
        catch { Dispose(); throw; }
        finally { _send.Release(); }
    }
    public async ValueTask<MeshDatagram> ReceiveAsync(CancellationToken token = default)
    {
        await _receive.WaitAsync(token);
        try { return await LocalDatagramProtocol.Read(_stream, token); }
        catch { Dispose(); throw; }
        finally { _receive.Release(); }
    }
    public void Dispose() => _stream.Dispose();
}

internal static class LocalDatagramProtocol
{
    internal static async ValueTask Write(Stream stream, IPEndPoint endpoint, ReadOnlyMemory<byte> payload, CancellationToken ct, IPEndPoint? external = null, ushort sourceNode = 0)
    {
        if (payload.Length > 60000) throw new ArgumentOutOfRangeException(nameof(payload));
        byte[] frame = new byte[42 + payload.Length];
        EndpointCodec.Write(frame.AsSpan(0, 19), endpoint);
        if (external != null) EndpointCodec.Write(frame.AsSpan(19, 19), external);
        WriteUInt16BigEndian(frame.AsSpan(38), sourceNode);
        WriteUInt16BigEndian(frame.AsSpan(40), (ushort)payload.Length);
        payload.CopyTo(frame.AsMemory(42));
        await stream.WriteAsync(frame, ct);
    }
    internal static async ValueTask<MeshDatagram> Read(Stream stream, CancellationToken ct)
    {
        byte[] header = new byte[42];
        await stream.ReadExactlyAsync(header, ct);
        int count = ReadUInt16BigEndian(header.AsSpan(40));
        if (count > 60000) throw new InvalidDataException("Oversized datagram.");
        byte[] payload = new byte[count];
        await stream.ReadExactlyAsync(payload, ct);
        return new(EndpointCodec.Read(header), payload, header[19] == 0 ? null : EndpointCodec.Read(header.AsSpan(19)), ReadUInt16BigEndian(header.AsSpan(38)));
    }
}
