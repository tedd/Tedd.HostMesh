using System.Net;
using System.Net.Quic;
using System.Threading.Channels;
using static System.Buffers.Binary.BinaryPrimitives;

namespace Tedd.HostMesh;

public sealed record DestinationRule(System.Net.IPNetwork Network, int? Port = null)
{
    public bool Allows(IPEndPoint endpoint) => (Port == null || Port == endpoint.Port) && Network.Contains(endpoint.Address);
}

public sealed record ApplicationGrant(string Name, IPAddress Address, IReadOnlyList<DestinationRule> Connect, bool MayReportOrigin = false);

public sealed record PeerContext(IPEndPoint MeshEndPoint, IPEndPoint? ExternalEndPoint, ushort SourceNode)
{
    public IPEndPoint EffectiveEndPoint => ExternalEndPoint ?? MeshEndPoint;
}

public sealed class MeshConnection : IAsyncDisposable
{
    private readonly FlowStream _stream;
    internal MeshConnection(QuicStream stream, IPEndPoint local, PeerContext peer)
    {
        _stream = new FlowStream(stream);
        LocalEndPoint = local;
        Peer = peer;
    }
    public Stream Stream => _stream;
    public IPEndPoint LocalEndPoint { get; }
    public PeerContext Peer { get; }
    public void CompleteWrites() => _stream.CompleteWritesAsync().AsTask().GetAwaiter().GetResult();
    public ValueTask CompleteWritesAsync(CancellationToken token = default) => _stream.CompleteWritesAsync(token);
    public void Abort() => _stream.Abort();
    public ValueTask DisposeAsync() => _stream.DisposeAsync();
}

public sealed class MeshListener : IAsyncDisposable
{
    private readonly Channel<MeshConnection> _queue = Channel.CreateBounded<MeshConnection>(32);
    private readonly Action _release;
    internal MeshListener(Action release) => _release = release;
    private readonly SemaphoreSlim _slots = new(32, 32);
    internal bool Reserve() => !_queue.Reader.Completion.IsCompleted && _slots.Wait(0);
    internal void CancelReservation() => _slots.Release();
    internal bool Enqueue(MeshConnection connection) => _queue.Writer.TryWrite(connection);
    public async ValueTask<MeshConnection> AcceptAsync(CancellationToken cancellationToken = default)
    {
        var connection = await _queue.Reader.ReadAsync(cancellationToken);
        _slots.Release();
        return connection;
    }
    public async ValueTask DisposeAsync()
    {
        _release();
        _queue.Writer.TryComplete();
        while (_queue.Reader.TryRead(out var connection)) await connection.DisposeAsync();
    }
}

public readonly record struct MeshDatagram(IPEndPoint Source, byte[] Payload, IPEndPoint? ExternalEndPoint = null, ushort SourceNode = 0)
{
    public PeerContext Peer => new(Source, ExternalEndPoint, SourceNode);
}

public sealed class MeshDatagramSocket : IDisposable
{
    private readonly MeshApplication _app;
    private readonly Action _release;
    private readonly Channel<MeshDatagram> _queue = Channel.CreateBounded<MeshDatagram>(128);
    private int _disposed;
    internal MeshDatagramSocket(MeshApplication app, IPEndPoint local, Action release) => (_app, LocalEndPoint, _release) = (app, local, release);
    public IPEndPoint LocalEndPoint { get; }
    internal void Deliver(MeshDatagram message) => _queue.Writer.TryWrite(message);
    public bool SendTo(IPEndPoint destination, ReadOnlySpan<byte> bytes)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        return _app.SendDatagram(LocalEndPoint, destination, bytes, null);
    }
    internal bool SendFrom(IPEndPoint destination, ReadOnlySpan<byte> bytes, IPEndPoint external)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        return _app.SendDatagram(LocalEndPoint, destination, bytes, external);
    }
    public ValueTask<MeshDatagram> ReceiveAsync(CancellationToken cancellationToken = default) => _queue.Reader.ReadAsync(cancellationToken);
    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        _release(); _queue.Writer.TryComplete();
    }
}

public sealed class MeshApplication
{
    private readonly MeshAgent _agent;
    internal ApplicationGrant Grant { get; }
    internal MeshApplication(MeshAgent agent, ApplicationGrant grant) => (_agent, Grant) = (agent, grant);
    public IPAddress Address => Grant.Address;
    internal MeshListener ListenTarget(int port, IPEndPoint target, System.Net.IPNetwork[] acl, bool proxyProtocol = false) =>
        _agent.Listen(new(Address, port), acl, target, proxyProtocol);
    internal MeshDatagramSocket BindEphemeral(System.Net.IPNetwork source)
    {
        for (int i = 0; i < 64; i++)
        {
            try { return BindDatagram(Random.Shared.Next(49152, 65536), source); }
            catch (IOException) when (i < 63) { }
        }
        throw new IOException("UDP association limit reached.");
    }
    public MeshListener Listen(int port, params System.Net.IPNetwork[] allowedSources) =>
        _agent.Listen(new(Address, port), allowedSources);

    public Task<MeshConnection> ConnectAsync(IPEndPoint destination, CancellationToken cancellationToken = default) =>
        ConnectFromAsync(destination, null, cancellationToken);

    public Task<MeshConnection> ConnectFromAsync(IPEndPoint destination, IPEndPoint? external, CancellationToken cancellationToken = default)
    {
        Authorize(destination);
        if (external != null && !Grant.MayReportOrigin) throw new UnauthorizedAccessException("Application cannot attest external addresses.");
        return _agent.ConnectAsync(this, destination, external, cancellationToken);
    }

    public MeshDatagramSocket BindDatagram(int port, params System.Net.IPNetwork[] allowedSources) =>
        _agent.BindDatagram(this, new(Address, port), allowedSources);

    internal bool SendDatagram(IPEndPoint local, IPEndPoint destination, ReadOnlySpan<byte> bytes, IPEndPoint? external)
    {
        Authorize(destination);
        if (external != null && !Grant.MayReportOrigin) throw new UnauthorizedAccessException("Application cannot attest external addresses.");
        return _agent.SendDatagram(local, destination, bytes, external);
    }

    internal void AuthorizeIngress(IPEndPoint destination)
    {
        Authorize(destination);
        if (!Grant.MayReportOrigin || !_agent.Router.Membership[_agent.Router.Id].Ingress)
            throw new UnauthorizedAccessException("A physical ingress requires an authorized node and application.");
    }

    private void Authorize(IPEndPoint destination)
    {
        if (!Grant.Connect.Any(r => r.Allows(destination))) throw new UnauthorizedAccessException("Destination denied.");
    }
}

internal static class EndpointCodec
{
    internal const int Size = 19;
    internal static void Write(Span<byte> target, IPEndPoint endpoint)
    {
        target.Clear();
        var bytes = endpoint.Address.GetAddressBytes();
        target[0] = (byte)bytes.Length;
        bytes.CopyTo(target[1..]);
        WriteUInt16BigEndian(target[17..], (ushort)endpoint.Port);
    }
    internal static IPEndPoint Read(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length < Size || bytes[0] is not (4 or 16)) throw new InvalidDataException("Invalid endpoint.");
        return new IPEndPoint(new IPAddress(bytes.Slice(1, bytes[0])), ReadUInt16BigEndian(bytes[17..]));
    }
}

public static class ReliableMessages
{
    public static async ValueTask WriteAsync(Stream stream, ReadOnlyMemory<byte> message, CancellationToken token = default)
    {
        if (message.Length > 1_048_576) throw new ArgumentOutOfRangeException(nameof(message));
        var frame = new byte[message.Length + 4];
        WriteInt32BigEndian(frame, message.Length);
        message.CopyTo(frame.AsMemory(4));
        await stream.WriteAsync(frame, token);
    }

    public static async ValueTask<byte[]> ReadAsync(Stream stream, CancellationToken token = default)
    {
        byte[] size = new byte[4];
        await stream.ReadExactlyAsync(size, token);
        int length = ReadInt32BigEndian(size);
        if ((uint)length > 1_048_576) throw new InvalidDataException("Invalid message length.");
        byte[] data = new byte[length];
        await stream.ReadExactlyAsync(data, token);
        return data;
    }
}
