using System.Net;
using System.Net.Sockets;
using Tedd.HostMesh.Simulation;

namespace Tedd.HostMesh.Tests;

public sealed class EndpointTests(Identities keys) : IClassFixture<Identities>
{
    private sealed class Pair : IAsyncDisposable
    {
        internal readonly SimulatedNetwork Net = new(99);
        internal MeshAgent A = null!, B = null!;
        internal async Task Start(Identities keys, TimeSpan? outage = null)
        {
            var members = keys.Membership();
            Net.AllowDial(1, 2);
            A = await MeshAgent.StartAsync(1, members, keys.Keys[1], Net.Attach(1), [Identities.App(1)], outage);
            B = await MeshAgent.StartAsync(2, members, keys.Keys[2], Net.Attach(2), [Identities.App(2)], outage);
            using var timeout = new CancellationTokenSource(5000);
            await FlowTests.Until(() => A.Router.Routes.ContainsKey(2) && B.Router.Routes.ContainsKey(1), timeout.Token);
        }
        public async ValueTask DisposeAsync() => await Task.WhenAll(A.DisposeAsync().AsTask(), B.DisposeAsync().AsTask());
    }

    [Fact] public async Task BindConflictsAreExclusivePerProtocolAndReleasedOnDispose()
    {
        await using var pair = new Pair(); await pair.Start(keys);
        var a = pair.A.Register("app");
        await using var listener = a.Listen(432, Identities.Prefix);
        using var udp = a.BindDatagram(432, Identities.Prefix);
        Assert.Throws<IOException>(() => a.Listen(432));
        Assert.Throws<IOException>(() => a.BindDatagram(432));
        udp.Dispose(); await listener.DisposeAsync();
        await using var replacement = a.Listen(432);
        using var replacementUdp = a.BindDatagram(432);
        Assert.Throws<UnauthorizedAccessException>(() => pair.A.Register("unknown"));
    }

    [Fact] public async Task DeniedListenersAndEgressAreEnforcedWithoutDeliveringAConnection()
    {
        await using var pair = new Pair(); await pair.Start(keys);
        var a = pair.A.Register("app");
        await using var listener = pair.B.Register("app").Listen(4321, System.Net.IPNetwork.Parse("192.0.2.0/24"));
        await Assert.ThrowsAnyAsync<IOException>(() => a.ConnectAsync(new(Identities.Address(2), 4321)));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => a.ConnectAsync(IPEndPoint.Parse("192.0.2.5:443")));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => pair.B.Register("app").ConnectFromAsync(new(Identities.Address(1), 443), IPEndPoint.Parse("192.0.2.5:3333")));
        using var deadline = new CancellationTokenSource(75);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await listener.AcceptAsync(deadline.Token));
    }

    [Fact] public async Task FragmentedUdpFlowsKeepIndependentPhysicalReplySockets()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(12)); var ct = timeout.Token;
        await using var pair = new Pair(); await pair.Start(keys);
        using var backend = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        await using var target = pair.B.Register("app").ForwardUdp(5000, (IPEndPoint)backend.Client.LocalEndPoint!, Identities.Prefix);
        await using var ingress = pair.A.Register("app").ListenUdp(new(IPAddress.Loopback, 0), new(Identities.Address(2), 5000), System.Net.IPNetwork.Parse("127.0.0.0/8"));
        using var c1 = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        using var c2 = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var distinctPeers = new HashSet<IPEndPoint>();
        for (int round = 0; round < 2; round++)
        {
            foreach (var (socket, value) in new[] { (c1, (byte)1), (c2, (byte)2) })
            {
                var payload = Enumerable.Repeat(value, 9000 + round).ToArray();
                await socket.SendAsync(payload, (IPEndPoint)ingress.LocalEndPoint!, ct);
                var request = await backend.ReceiveAsync(ct);
                Assert.Equal(payload, request.Buffer);
                distinctPeers.Add(request.RemoteEndPoint);
                await backend.SendAsync(request.Buffer, request.RemoteEndPoint, ct);
                Assert.Equal(payload, (await socket.ReceiveAsync(ct)).Buffer);
            }
        }
        Assert.Equal(2, distinctPeers.Count);
    }

    [Fact] public async Task ADeadEndpointTerminatesOldStreamAndANewSessionCanConnect()
    {
        await using var pair = new Pair();
        await pair.Start(keys, TimeSpan.FromSeconds(3));
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(25));
        var ct = timeout.Token;
        var a = pair.A.Register("app");
        var target = new IPEndPoint(Identities.Address(2), 1222);
        await using var oldListener = pair.B.Register("app").Listen(1222, Identities.Prefix);
        await using var oldClient = await a.ConnectAsync(target, ct);
        await using var oldServer = await oldListener.AcceptAsync(ct);
        pair.Net.Kill(2);
        // No transport close notification is delivered to A.
        var error = await Record.ExceptionAsync(async () => await oldClient.Stream.ReadExactlyAsync(new byte[1], ct));
        Assert.IsAssignableFrom<IOException>(error);
        Assert.False(ct.IsCancellationRequested);
        await pair.B.DisposeAsync();
        pair.B = await MeshAgent.StartAsync(2, keys.Membership(), keys.Keys[2], pair.Net.Attach(2), [Identities.App(2)]);
        await using var listener = pair.B.Register("app").Listen(1222, Identities.Prefix);
        await FlowTests.Until(() => pair.A.Router.Routes.ContainsKey(2) && pair.B.Router.Routes.ContainsKey(1), ct);
        await using var restored = await a.ConnectAsync(target, ct);
        await using var server = await listener.AcceptAsync(ct);
        await restored.Stream.WriteAsync(new byte[] { 89 }, ct);
        byte[] got = new byte[1]; await server.Stream.ReadExactlyAsync(got, ct);
        Assert.Equal(89, got[0]);
    }

    [Fact] public async Task SlowConsumerOnOneStreamAllowsAnotherStreamToComplete()
    {
        await using var pair = new Pair(); await pair.Start(keys);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var ct = timeout.Token;
        var app = pair.A.Register("app");
        await using var listener = pair.B.Register("app").Listen(512, Identities.Prefix);
        var target = new IPEndPoint(Identities.Address(2), 512);
        await using var bulk = await app.ConnectAsync(target, ct);
        await using var slow = await listener.AcceptAsync(ct);
        using var end = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var write = bulk.Stream.WriteAsync(new byte[8 * 1024 * 1024], end.Token).AsTask();
        await using var other = await app.ConnectAsync(target, ct);
        await using var fast = await listener.AcceptAsync(ct);
        await other.Stream.WriteAsync(new byte[] { 7 }, ct);
        byte[] buf = new byte[1]; await fast.Stream.ReadExactlyAsync(buf, ct);
        Assert.Equal(7, buf[0]);
        Assert.False(write.IsCompleted);
        end.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await write);
    }

    [Fact] public async Task BackendRefusalFailsTheMeshOpenBeforeAnyDataIsAccepted()
    {
        await using var pair = new Pair(); await pair.Start(keys);
        // Binding without Listen reserves the port but refuses connects on both supported platforms.
        using var reserved = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        reserved.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        await using var forward = pair.B.Register("app").ForwardTcp(6800, (IPEndPoint)reserved.LocalEndPoint!, Identities.Prefix);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(8));
        await Assert.ThrowsAnyAsync<IOException>(() => pair.A.Register("app").ConnectAsync(new(Identities.Address(2), 6800), deadline.Token));
    }

    [Fact] public async Task RevocationTerminatesAnAdmittedFlowAndDeniesNewOpens()
    {
        await using var pair = new Pair(); await pair.Start(keys);
        var app = pair.A.Register("app");
        var target = new IPEndPoint(Identities.Address(2), 6770);
        await using var service = pair.B.Register("app").Listen(6770, Identities.Prefix);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(12));
        await using var client = await app.ConnectAsync(target, timeout.Token);
        await using var server = await service.AcceptAsync(timeout.Token);
        await pair.A.SetRevokedNodesAsync([2]);
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => app.ConnectAsync(target, timeout.Token));
        var failure = await Record.ExceptionAsync(async () => await client.Stream.ReadExactlyAsync(new byte[1], timeout.Token));
        Assert.True(failure is IOException or ObjectDisposedException);
    }

    [Fact] public async Task ConcurrentWritersOnOneStreamKeepEachReliableMessageIntact()
    {
        await using var pair = new Pair(); await pair.Start(keys);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(25));
        var ct = timeout.Token;
        await using var listener = pair.B.Register("app").Listen(4600, Identities.Prefix);
        await using var client = await pair.A.Register("app").ConnectAsync(new(Identities.Address(2), 4600), ct);
        await using var server = await listener.AcceptAsync(ct);
        // Each frame exceeds the native send chunk and can span many mesh packets.
        var writing = Enumerable.Range(1, 12).Select(id => Task.Run(async () =>
            await ReliableMessages.WriteAsync(client.Stream, Enumerable.Repeat((byte)id, 35000 + id).ToArray(), ct), ct)).ToArray();
        var unique = new HashSet<int>();
        for (int i = 0; i < writing.Length; i++)
        {
            var frame = await ReliableMessages.ReadAsync(server.Stream, ct);
            Assert.Equal(35000 + frame[0], frame.Length);
            Assert.True(frame.All(value => value == frame[0]));
            Assert.True(unique.Add(frame[0]));
        }
        await Task.WhenAll(writing);
        await client.CompleteWritesAsync(ct);
        Assert.Equal(0, await server.Stream.ReadAsync(new byte[1], ct));
    }

    [Fact] public async Task ExternalUdpClientProvenanceIsAttestedAndReturnAddressIsRoutable()
    {
        await using var pair = new Pair(); await pair.Start(keys);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(6));
        var ct = timeout.Token;
        using var server = pair.B.Register("app").BindDatagram(4601, Identities.Prefix);
        await using var ingress = pair.A.Register("app").ListenUdp(new(IPAddress.Loopback, 0), server.LocalEndPoint, System.Net.IPNetwork.Parse("127.0.0.0/8"));
        using var external = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        await external.SendAsync(new byte[] { 24 }, (IPEndPoint)ingress.LocalEndPoint!, ct);
        var received = await server.ReceiveAsync(ct);
        Assert.Equal(external.Client.LocalEndPoint, received.Peer.EffectiveEndPoint);
        Assert.Equal(Identities.Address(1), received.Source.Address);
        Assert.Equal((ushort)1, received.SourceNode);
        Assert.True(server.SendTo(received.Source, received.Payload));
        Assert.Equal(new byte[] { 24 }, (await external.ReceiveAsync(ct)).Buffer);
    }

    [Fact] public void LatencyTrafficCanPreferANarrowDirectLinkAndHonorAdministrativeCost()
    {
        var lab = new Lab(keys);
        lab.Diamond();
        lab.Network.AllowDial(1, 4);
        lab.Network.Configure(1, 4, new(new(20_000), 1));
        lab.Advance(1500);
        Assert.Equal((ushort)2, lab.Nodes[1].Routes[4].NextHop);
        Assert.Equal((ushort)4, lab.Nodes[1].InteractiveRoutes[4].NextHop);
        lab.Nodes[1].Preference = RoutingClass.Latency;
        long before = lab.Nodes[2].Counters.ForwardedPackets;
        Assert.True(lab.Nodes[1].SendPayload(4, [1]));
        lab.Advance(60);
        Assert.Equal(before, lab.Nodes[2].Counters.ForwardedPackets);
        lab.Nodes[1].SetLinkCost(4, 50);
        lab.Advance(100);
        Assert.Equal((ushort)2, lab.Nodes[1].InteractiveRoutes[4].NextHop);
    }
}
