using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using static System.Buffers.Binary.BinaryPrimitives;

namespace Tedd.HostMesh;

public static class LocalMeshServer
{
    public static SocketForward Listen(MeshApplication application, string socketPath, ReadOnlySpan<byte> applicationKey,
        params System.Net.IPNetwork[] allowedMeshSources)
    {
        if (applicationKey.Length != 32) throw new ArgumentException("An application key must be 32 bytes.");
        var key = applicationKey.ToArray();
        var registrations = new ConcurrentDictionary<int, MeshListener>();
        var listener = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        try { listener.Bind(new UnixDomainSocketEndPoint(socketPath)); listener.Listen(64); }
        catch { listener.Dispose(); throw; }
        return new SocketForward(async (owner, ct) =>
        {
            while (!ct.IsCancellationRequested)
            {
                var socket = await listener.AcceptAsync(ct);
                if (!owner.HasCapacity) { socket.Dispose(); continue; }
                owner.Run(Handle(socket, ct));
            }
        }, listener.Dispose);

        async Task Handle(Socket socket, CancellationToken ct)
        {
            using (socket)
            using (var stream = new NetworkStream(socket, false))
            using (var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct))
            {
                timeout.CancelAfter(TimeSpan.FromSeconds(5));
                byte[] request = new byte[53];
                await stream.ReadExactlyAsync(request, timeout.Token);
                if (request[0] != 1 || !CryptographicOperations.FixedTimeEquals(request.AsSpan(1, 32), key)) return;
                var ep = EndpointCodec.Read(request.AsSpan(34));
                switch (request[33])
                {
                    case 1:
                        await Serve(await application.ConnectAsync(ep, ct));
                        break;
                    case 2:
                        await using (var registration = application.Listen(ep.Port, allowedMeshSources))
                        {
                            if (!registrations.TryAdd(ep.Port, registration)) return;
                            try
                            {
                                await stream.WriteAsync(new byte[] { 1 }, ct);
                                if (await stream.ReadAsync(new byte[1], ct) != 0) throw new InvalidDataException("Unexpected listener control message.");
                            }
                            finally { registrations.TryRemove(new KeyValuePair<int, MeshListener>(ep.Port, registration)); }
                        }
                        break;
                    case 3:
                        if (registrations.TryGetValue(ep.Port, out var service))
                        {
                            // A pending accept must leave the queue if the local caller cancels.
                            using var disconnected = CancellationTokenSource.CreateLinkedTokenSource(ct);
                            var monitor = WatchDisconnect(socket, disconnected);
                            MeshConnection flow;
                            try { flow = await service.AcceptAsync(disconnected.Token); }
                            finally { disconnected.Cancel(); await monitor; }
                            await Serve(flow);
                        }
                        break;
                    case 4:
                        using (var binding = application.BindDatagram(ep.Port, allowedMeshSources))
                        using (var linked = CancellationTokenSource.CreateLinkedTokenSource(ct))
                        {
                            await stream.WriteAsync(new byte[] { 1 }, ct);
                            async Task Send()
                            {
                                while (true)
                                {
                                    var message = await LocalDatagramProtocol.Read(stream, linked.Token);
                                    binding.SendTo(message.Source, message.Payload);
                                }
                            }
                            async Task Receive()
                            {
                                while (true)
                                {
                                    var message = await binding.ReceiveAsync(linked.Token);
                                    await LocalDatagramProtocol.Write(stream, message.Source, message.Payload, linked.Token, message.ExternalEndPoint, message.SourceNode);
                                }
                            }
                            var send = Send(); var receive = Receive();
                            await Task.WhenAny(send, receive);
                            linked.Cancel();
                            await Task.WhenAll(send, receive);
                        }
                        break;
                }

                async Task Serve(MeshConnection connection)
                {
                    await using (connection)
                    {
                        byte[] header = new byte[60];
                        header[0] = 1;
                        EndpointCodec.Write(header.AsSpan(1, 19), connection.LocalEndPoint);
                        EndpointCodec.Write(header.AsSpan(20, 19), connection.Peer.MeshEndPoint);
                        if (connection.Peer.ExternalEndPoint != null) EndpointCodec.Write(header.AsSpan(39, 19), connection.Peer.ExternalEndPoint);
                        WriteUInt16BigEndian(header.AsSpan(58), connection.Peer.SourceNode);
                        await stream.WriteAsync(header, ct);
                        await SocketForwards.CopyDuplex(socket, connection, ct);
                    }
                }
            }
        }
    }

    private static async Task WatchDisconnect(Socket socket, CancellationTokenSource stop)
    {
        try
        {
            await socket.ReceiveAsync(new byte[1], SocketFlags.Peek, stop.Token);
            stop.Cancel();
        }
        catch (OperationCanceledException) when (stop.IsCancellationRequested) { }
        catch (SocketException) { stop.Cancel(); }
    }
}
