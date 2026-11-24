using System.Collections.Concurrent;
using System.Net;
using System.Net.Quic;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using static System.Buffers.Binary.BinaryPrimitives;

namespace Tedd.HostMesh;

public sealed class MeshAgent : IAsyncDisposable
{
    private static readonly SslApplicationProtocol Alpn = new("hostmesh-flow/1");
    private readonly IMeshLinks _links;
    private readonly MeshMembership _members;
    private readonly X509Certificate2 _identity;
    private readonly Dictionary<string, ApplicationGrant> _grants;
    private readonly TimeSpan _outage;
    private readonly CancellationTokenSource _stop = new();
    private readonly ConcurrentDictionary<IPEndPoint, Service> _services = new();
    private readonly ConcurrentDictionary<IPEndPoint, (MeshDatagramSocket Socket, System.Net.IPNetwork[] Acl)> _udp = new();
    private readonly ConcurrentDictionary<ushort, Lazy<Task<Session>>> _outgoing = new();
    private readonly ConcurrentDictionary<Task, byte> _tasks = new();
    private readonly ConcurrentDictionary<QuicConnection, ushort> _incomingSessions = new();
    private QuicListener _listener = null!;
    private PacketTunnel _tunnel = null!;
    private Task _accept = null!, _pump = null!;
    private int _nextPort = Random.Shared.Next(16384), _disposed;
    private sealed record Session(QuicConnection Connection, Action Release);
    private sealed record Service(System.Net.IPNetwork[] Acl, MeshListener Listener, IPEndPoint? Target, bool ProxyProtocol);

    private MeshAgent(ushort id, MeshMembership members, X509Certificate2 identity, IMeshLinks links,
        IEnumerable<ApplicationGrant> grants, TimeSpan outage, long? generation)
    {
        Router = new(id, members, identity, links, generation: generation);
        _links = links;
        _members = members;
        _identity = identity;
        _outage = outage;
        _grants = grants.ToDictionary(g => g.Name, g => g with { Connect = g.Connect.ToArray() }, StringComparer.Ordinal);
        if (_grants.Values.Any(g => members.Owner(g.Address) != id) || _grants.Values.Select(g => g.Address).Distinct().Count() != _grants.Count)
            throw new ArgumentException("Each application requires an exclusive local mesh address.");
    }

    public MeshRouter Router { get; }
    private static QuicReceiveWindowSizes FlowWindows() => new()
    {
        Connection = 4 * 1024 * 1024,
        LocallyInitiatedBidirectionalStream = 65536,
        RemotelyInitiatedBidirectionalStream = 65536
    };

    public static async Task<MeshAgent> StartAsync(ushort id, MeshMembership members, X509Certificate2 identity,
        IMeshLinks links, IEnumerable<ApplicationGrant> grants, TimeSpan? outage = null, CancellationToken cancellationToken = default, long? generation = null, IEnumerable<ushort>? revokedNodes = null)
    {
        if (revokedNodes != null) members.Revoke(revokedNodes);
        var agent = new MeshAgent(id, members, identity, links, grants, outage ?? TimeSpan.FromSeconds(45), generation);
        try
        {
            agent._listener = await QuicListener.ListenAsync(new QuicListenerOptions
            {
                ListenEndPoint = new IPEndPoint(IPAddress.Loopback, 0),
                ApplicationProtocols = [Alpn],
                ConnectionOptionsCallback = (_, _, _) => ValueTask.FromResult(new QuicServerConnectionOptions
                {
                    DefaultCloseErrorCode = 1, DefaultStreamErrorCode = 2, InitialReceiveWindowSizes = FlowWindows(), MaxInboundBidirectionalStreams = 128,
                    IdleTimeout = agent._outage, KeepAliveInterval = agent._outage / 4,
                    ServerAuthenticationOptions = new SslServerAuthenticationOptions
                    {
                        ApplicationProtocols = [Alpn], ServerCertificate = identity, ClientCertificateRequired = true,
                        RemoteCertificateValidationCallback = (_, cert, _, _) => members.Identify(cert) != 0
                    }
                })
            }, cancellationToken);
            agent._tunnel = new PacketTunnel(agent.Router, agent._listener.LocalEndPoint, agent._outage, agent.ReceiveDatagram);
            agent._accept = agent.AcceptLoop();
            agent._pump = agent.Pump();
            return agent;
        }
        catch
        {
            if (agent._listener != null) await agent._listener.DisposeAsync();
            await links.DisposeAsync();
            throw;
        }
    }

    public MeshApplication Register(string name) => new(this, _grants.TryGetValue(name, out var grant) ? grant : throw new UnauthorizedAccessException("Unknown application."));

    internal MeshListener Listen(IPEndPoint address, System.Net.IPNetwork[] acl, IPEndPoint? target = null, bool proxyProtocol = false)
    {
        Service? service = null;
        var listener = new MeshListener(() => _services.TryRemove(new KeyValuePair<IPEndPoint, Service>(address, service!)));
        service = new(acl.ToArray(), listener, target, proxyProtocol);
        if (!_services.TryAdd(address, service)) throw new IOException("Mesh endpoint in use.");
        return listener;
    }

    internal MeshDatagramSocket BindDatagram(MeshApplication app, IPEndPoint address, System.Net.IPNetwork[] acl)
    {
        var rules = acl.ToArray();
        MeshDatagramSocket? socket = null;
        socket = new(app, address, () => _udp.TryRemove(new KeyValuePair<IPEndPoint, (MeshDatagramSocket, System.Net.IPNetwork[])>(address, (socket!, rules))));
        if (!_udp.TryAdd(address, (socket, rules))) throw new IOException("UDP endpoint in use.");
        return socket;
    }

    internal async Task<MeshConnection> ConnectAsync(MeshApplication app, IPEndPoint target, IPEndPoint? external, CancellationToken token)
    {
        ushort peer = _members.Owner(target.Address);
        if (!_members.Contains(peer) || !_members.Contains(Router.Id)) throw new UnauthorizedAccessException("Node membership revoked.");
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token, _stop.Token);
        deadline.CancelAfter(TimeSpan.FromSeconds(12));
        QuicStream stream = await OpenStreamAsync(peer, deadline.Token);
        try
        {
            var local = new IPEndPoint(app.Address, 49152 + (Interlocked.Increment(ref _nextPort) & 16383));
            var header = new byte[3 * EndpointCodec.Size];
            EndpointCodec.Write(header.AsSpan(0, 19), local);
            EndpointCodec.Write(header.AsSpan(19, 19), target);
            if (external != null) EndpointCodec.Write(header.AsSpan(38), external);
            await stream.WriteAsync(header, deadline.Token);
            byte[] ack = new byte[1];
            await stream.ReadExactlyAsync(ack, deadline.Token);
            if (ack[0] != 1) throw new IOException("Mesh destination refused the connection.");
            return new(stream, local, new(target, null, peer));
        }
        catch { await stream.DisposeAsync(); throw; }
    }

    private async Task<QuicStream> OpenStreamAsync(ushort peer, CancellationToken token, bool retry = true)
    {
        var lazy = _outgoing.GetOrAdd(peer, id => new(() => Dial(id), LazyThreadSafetyMode.ExecutionAndPublication));
        Session session;
        try { session = await lazy.Value.WaitAsync(token); }
        catch { if (lazy.Value.IsCompleted && !lazy.Value.IsCompletedSuccessfully) _outgoing.TryRemove(new KeyValuePair<ushort, Lazy<Task<Session>>>(peer, lazy)); throw; }
        try { return await session.Connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional, token); }
        catch (QuicException)
        {
            if (_outgoing.TryRemove(new KeyValuePair<ushort, Lazy<Task<Session>>>(peer, lazy)))
            {
                await session.Connection.DisposeAsync();
                session.Release();
            }
            // No application open has been sent on this stream. A fresh carrier is safe here.
            if (retry) return await OpenStreamAsync(peer, token, false);
            throw;
        }
    }

    private async Task<Session> Dial(ushort peer)
    {
        var (proxy, release) = _tunnel.Open(peer);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(_stop.Token);
        timeout.CancelAfter(TimeSpan.FromSeconds(10));
        try
        {
            var connection = await QuicConnection.ConnectAsync(new QuicClientConnectionOptions
            {
                RemoteEndPoint = proxy, DefaultCloseErrorCode = 1, DefaultStreamErrorCode = 2, InitialReceiveWindowSizes = FlowWindows(),
                IdleTimeout = _outage, KeepAliveInterval = _outage / 4,
                ClientAuthenticationOptions = new SslClientAuthenticationOptions
                {
                    TargetHost = "hostmesh", ApplicationProtocols = [Alpn],
                    ClientCertificates = new X509CertificateCollection { _identity },
                    LocalCertificateSelectionCallback = (_, _, _, _, _) => _identity,
                    RemoteCertificateValidationCallback = (_, cert, _, _) => _members.Contains(peer) && _members[peer].Matches(cert)
                }
            }, timeout.Token);
            if (!_members.Contains(peer) || !_members.Contains(Router.Id))
            {
                await connection.DisposeAsync();
                throw new UnauthorizedAccessException("Node membership revoked.");
            }
            return new(connection, release);
        }
        catch { release(); throw; }
    }

    private async Task Pump()
    {
        using var timer = new PeriodicTimer(TimeSpan.FromMilliseconds(4));
        try { while (await timer.WaitForNextTickAsync(_stop.Token)) Router.Tick(); }
        catch (OperationCanceledException) when (_stop.IsCancellationRequested) { }
    }

    private void Track(Task task)
    {
        _tasks.TryAdd(task, 0);
        _ = task.ContinueWith(t => { _ = t.Exception; _tasks.TryRemove(t, out _); },
            CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
    }

    private async Task AcceptLoop()
    {
        while (!_stop.IsCancellationRequested)
        {
            try { Track(Serve(await _listener.AcceptConnectionAsync(_stop.Token))); }
            catch (Exception ex) when (ex is QuicException or AuthenticationException or IOException) { }
            catch (OperationCanceledException) when (_stop.IsCancellationRequested) { break; }
        }
    }

    private async Task Serve(QuicConnection connection)
    {
        await using (connection)
        {
            ushort peer = _members.Identify(connection.RemoteCertificate);
            if (peer == 0) return;
            _incomingSessions.TryAdd(connection, peer);
            try
            {
                while (!_stop.IsCancellationRequested && _members.Contains(peer) && _members.Contains(Router.Id))
                    Track(Admit(await connection.AcceptInboundStreamAsync(_stop.Token), peer));
            }
            catch (Exception ex) when (ex is QuicException or OperationCanceledException or ObjectDisposedException) { }
            finally { _incomingSessions.TryRemove(connection, out _); }
        }
    }

    private async Task Admit(QuicStream stream, ushort peer)
    {
        bool transferred = false;
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(_stop.Token);
        timeout.CancelAfter(TimeSpan.FromSeconds(8));
        try
        {
            byte[] header = new byte[57];
            await stream.ReadExactlyAsync(header, timeout.Token);
            var source = EndpointCodec.Read(header);
            var target = EndpointCodec.Read(header.AsSpan(19));
            var external = header[38] == 0 ? null : EndpointCodec.Read(header.AsSpan(38));
            if (!_members.Contains(peer) || !_members.Contains(Router.Id) || _members.Owner(source.Address) != peer || external != null && !_members[peer].Ingress
                || !_services.TryGetValue(target, out var service) || !service.Acl.Any(r => r.Contains(source.Address))) return;
            var connection = new MeshConnection(stream, target, new(source, external, peer));
            if (service.Target is { } targetSocket)
            {
                var socket = new System.Net.Sockets.Socket(targetSocket.AddressFamily, System.Net.Sockets.SocketType.Stream, System.Net.Sockets.ProtocolType.Tcp);
                try
                {
                    await socket.ConnectAsync(targetSocket, timeout.Token);
                    if (service.ProxyProtocol)
                    {
                        using var backend = new System.Net.Sockets.NetworkStream(socket, false);
                        await backend.WriteAsync(SocketForwards.ProxyHeader(connection.Peer.EffectiveEndPoint, target), timeout.Token);
                    }
                    await stream.WriteAsync(new byte[] { 1 }, timeout.Token);
                    Track(SocketForwards.ServeTarget(socket, connection, _stop.Token));
                    transferred = true;
                }
                finally { if (!transferred) socket.Dispose(); }
                return;
            }
            // Publish after the acknowledgement so application writes cannot race the protocol preamble.
            if (!service.Listener.Reserve()) return;
            try
            {
                await stream.WriteAsync(new byte[] { 1 }, timeout.Token);
                transferred = service.Listener.Enqueue(connection);
            }
            finally { if (!transferred) service.Listener.CancelReservation(); }
        }
        finally
        {
            if (!transferred) await stream.DisposeAsync();
        }
    }

    internal bool SendDatagram(IPEndPoint source, IPEndPoint target, ReadOnlySpan<byte> bytes, IPEndPoint? external)
    {
        if (bytes.Length > 60_000) throw new ArgumentOutOfRangeException(nameof(bytes));
        byte[] body = new byte[75 + bytes.Length];
        EndpointCodec.Write(body.AsSpan(0, 19), source); EndpointCodec.Write(body.AsSpan(19, 19), target);
        WriteInt64BigEndian(body.AsSpan(38), DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        RandomNumberGenerator.Fill(body.AsSpan(46, 8));
        WriteUInt16BigEndian(body.AsSpan(54), (ushort)bytes.Length);
        if (external != null) EndpointCodec.Write(body.AsSpan(56, 19), external);
        bytes.CopyTo(body.AsSpan(75));
        return _tunnel.Send(_members.Owner(target.Address), 3, 0, [.. body, .. IdentityProof.Sign(_identity, ProofPurpose.Datagram, body)]);
    }

    private void ReceiveDatagram(ushort peer, byte[] bytes)
    {
        if (bytes.Length < 76) return;
        int end = 75 + ReadUInt16BigEndian(bytes.AsSpan(54));
        if (end >= bytes.Length) return;
        long stamp = ReadInt64BigEndian(bytes.AsSpan(38)), now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        if (stamp < now - 60 || stamp > now + 60 || !_members[peer].Verify(ProofPurpose.Datagram, bytes.AsSpan(0, end), bytes.AsSpan(end))) return;
        try
        {
            var source = EndpointCodec.Read(bytes);
            var external = bytes[56] == 0 ? null : EndpointCodec.Read(bytes.AsSpan(56));
            if ((external == null || _members[peer].Ingress) && _members.Owner(source.Address) == peer && _udp.TryGetValue(EndpointCodec.Read(bytes.AsSpan(19)), out var entry)
                && entry.Acl.Any(r => r.Contains(source.Address))) entry.Socket.Deliver(new(source, bytes[75..end], external, peer));
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidDataException) { }
    }

    public async Task SetRevokedNodesAsync(IEnumerable<ushort> nodes)
    {
        _members.Revoke(nodes);
        Router.Tick();
        foreach (var (connection, peer) in _incomingSessions)
            if (!_members.Contains(peer) || !_members.Contains(Router.Id))
                await connection.DisposeAsync();
        foreach (var item in _outgoing)
        {
            if (_members.Contains(item.Key) && _members.Contains(Router.Id) || !_outgoing.TryRemove(item)) continue;
            if (!item.Value.IsValueCreated) continue;
            Session session;
            try { session = await item.Value.Value; } catch (Exception) { continue; }
            await session.Connection.DisposeAsync();
            session.Release();
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        Router.Stop();
        await Router.DrainWithdrawalAsync();
        _stop.Cancel();
        await Task.WhenAll(_pump, _accept);
        await _listener.DisposeAsync();
        foreach (var item in _services.Values) await item.Listener.DisposeAsync();
        foreach (var item in _udp.Values) item.Socket.Dispose();
        foreach (var item in _outgoing.Values)
        {
            if (!item.IsValueCreated) continue;
            Session session;
            try { session = await item.Value; } catch (Exception) { continue; }
            await session.Connection.DisposeAsync();
            session.Release();
        }
        while (!_tasks.IsEmpty) { try { await Task.WhenAll(_tasks.Keys); } catch (Exception) { } }
        await _tunnel.DisposeAsync();
        await _links.DisposeAsync();
        _stop.Dispose();
    }
}
