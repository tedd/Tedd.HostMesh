using System.Net;
using System.Net.Sockets;
using Tedd.HostMesh.Simulation;

namespace Tedd.HostMesh.Tests;

public sealed class FlowTests(Identities keys) : IClassFixture<Identities>
{
    internal static async Task Until(Func<bool> ready, CancellationToken token)
    {
        while (!ready()) await Task.Delay(15, token);
    }

    private sealed class Cluster : IAsyncDisposable
    {
        internal readonly SimulatedNetwork Net = new(1027);
        internal readonly Dictionary<ushort, MeshAgent> Agents = [];
        internal async Task Start(Identities keys)
        {
            var members = keys.Membership();
            Net.AllowDial(1, 2); Net.AllowDial(1, 3);
            Net.AllowDial(4, 2); Net.AllowDial(4, 3);
            for (ushort i = 1; i <= 4; i++)
                Agents[i] = await MeshAgent.StartAsync(i, members, keys.Keys[i], Net.Attach(i), [Identities.App(i)]);
        }
        public async ValueTask DisposeAsync() => await Task.WhenAll(Agents.Values.Select(a => a.DisposeAsync().AsTask()));
    }

    [Theory]
    [InlineData("kill")] [InlineData("graceful")] [InlineData("speed")] [InlineData("partition")]
    public async Task FullDuplexStreamRetainsBothHandlesAcrossRouteChange(string fault)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(35));
        var ct = timeout.Token;
        await using var cluster = new Cluster();
        await cluster.Start(keys);
        var a = cluster.Agents[1];
        var d = cluster.Agents[4];
        await Until(() => a.Router.Routes.GetValueOrDefault((ushort)4)?.NextHop == 2 && d.Router.Routes.ContainsKey(1), ct);
        var app = a.Register("app");
        await using var listener = d.Register("app").Listen(443, Identities.Prefix);
        var publicClient = IPEndPoint.Parse("203.0.113.44:5678");
        await using var client = await app.ConnectFromAsync(new(Identities.Address(4), 443), publicClient, ct);
        await using var server = await listener.AcceptAsync(ct);
        Assert.Equal(publicClient, server.Peer.EffectiveEndPoint);
        Assert.Equal(client.LocalEndPoint, server.Peer.MeshEndPoint);
        Assert.Equal((ushort)1, server.Peer.SourceNode);

        byte[] request = new byte[192 * 1024], response = new byte[160 * 1024];
        new Random(17).NextBytes(request); new Random(99).NextBytes(response);
        // Establish both byte sequences and leave real unacknowledged packets on the old path.
        await client.Stream.WriteAsync(request.AsMemory(0, 4096), ct);
        await server.Stream.WriteAsync(response.AsMemory(0, 4096), ct);
        var forward = Receive(server, request.Length, ct);
        var reverse = Receive(client, response.Length, ct);
        cluster.Net.Configure(1, 2, new(new(loss: .05), 90, 20, .03));
        var sendClient = client.Stream.WriteAsync(request.AsMemory(4096, 65536), ct).AsTask();
        var sendServer = server.Stream.WriteAsync(response.AsMemory(4096, 65536), ct).AsTask();

        if (fault == "kill") cluster.Net.Kill(2);
        if (fault == "graceful") await cluster.Agents[2].DisposeAsync();
        if (fault == "speed") cluster.Agents[2].Router.Conditions = new(8000);
        if (fault == "partition")
        {
            cluster.Net.Configure(1, 2, new(new(loss: 1))); cluster.Net.Configure(1, 3, new(new(loss: 1)));
            await Until(() => !a.Router.Routes.ContainsKey(4), ct);
            cluster.Net.Configure(1, 3, new(LinkConditions.Unlimited));
        }
        await Until(() => a.Router.Routes.GetValueOrDefault((ushort)4)?.NextHop == 3, ct);
        await Task.WhenAll(sendClient, sendServer);
        await Task.WhenAll(client.Stream.WriteAsync(request.AsMemory(69632), ct).AsTask(), server.Stream.WriteAsync(response.AsMemory(69632), ct).AsTask());
        client.CompleteWrites(); server.CompleteWrites();
        Assert.Equal(request, await forward);
        Assert.Equal(response, await reverse);
        Assert.True(cluster.Agents[3].Router.Counters.ForwardedPackets > 0);
        using var noSecondAccept = new CancellationTokenSource(80);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await listener.AcceptAsync(noSecondAccept.Token));
    }

    private static async Task<byte[]> Receive(MeshConnection connection, int length, CancellationToken ct)
    {
        byte[] data = new byte[length];
        await connection.Stream.ReadExactlyAsync(data, ct);
        Assert.Equal(0, await connection.Stream.ReadAsync(new byte[1], ct));
        return data;
    }

    [Fact] public async Task ParallelConnectsKeepBytesAndRemoteApplicationIsolated()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var ct = timeout.Token;
        await using var cluster = new Cluster();
        await cluster.Start(keys);
        var a = cluster.Agents[1];
        var d = cluster.Agents[4];
        await Until(() => a.Router.Routes.ContainsKey(4) && d.Router.Routes.ContainsKey(1), ct);
        await using var listener = d.Register("app").Listen(8400, Identities.Prefix);
        var accepting = Enumerable.Range(0, 24).Select(async _ =>
        {
            await using var s = await listener.AcceptAsync(ct);
            var message = await ReliableMessages.ReadAsync(s.Stream, ct);
            await ReliableMessages.WriteAsync(s.Stream, message, ct);
        }).ToArray();
        var opening = Enumerable.Range(0, 24).Select(async i =>
        {
            await using var c = await a.Register("app").ConnectAsync(new(Identities.Address(4), 8400), ct);
            byte[] data = BitConverter.GetBytes(i);
            await ReliableMessages.WriteAsync(c.Stream, data, ct);
            Assert.Equal(data, await ReliableMessages.ReadAsync(c.Stream, ct));
        });
        await Task.WhenAll(opening.Concat(accepting));
    }

    [Fact] public async Task DatagramReplyKeepsItsAddressAcrossLossAndReroute()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        await using var cluster = new Cluster();
        await cluster.Start(keys);
        var a = cluster.Agents[1]; var d = cluster.Agents[4];
        await Until(() => a.Router.Routes.ContainsKey(4) && d.Router.Routes.ContainsKey(1), timeout.Token);
        using var client = a.Register("app").BindDatagram(5432, Identities.Prefix);
        using var server = d.Register("app").BindDatagram(1234, Identities.Prefix);
        byte[] data = new byte[16384]; new Random(12).NextBytes(data);
        Assert.True(client.SendTo(server.LocalEndPoint, data));
        var received = await server.ReceiveAsync(timeout.Token);
        Assert.Equal(client.LocalEndPoint, received.Source);
        Assert.Equal(data, received.Payload);
        cluster.Net.Kill(2);
        await Until(() => d.Router.Routes.GetValueOrDefault((ushort)1)?.NextHop == 3, timeout.Token);
        Assert.True(server.SendTo(received.Source, [123]));
        var reply = await client.ReceiveAsync(timeout.Token);
        Assert.Equal(server.LocalEndPoint, reply.Source);
        Assert.Equal(new byte[] { 123 }, reply.Payload);
    }

    [Fact] public async Task EightDuplexStreamsSurviveRepeatedSpeedChangesAndARelayRestart()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(45));
        var ct = timeout.Token;
        await using var cluster = new Cluster();
        await cluster.Start(keys);
        var a = cluster.Agents[1]; var d = cluster.Agents[4];
        await Until(() => a.Router.Routes.ContainsKey(4) && d.Router.Routes.ContainsKey(1), ct);
        await using var listener = d.Register("app").Listen(4602, Identities.Prefix);
        var pairs = new List<(MeshConnection Client, MeshConnection Server)>();
        try
        {
            for (int i = 0; i < 8; i++)
            {
                var client = await a.Register("app").ConnectAsync(new(Identities.Address(4), 4602), ct);
                pairs.Add((client, await listener.AcceptAsync(ct)));
            }
            for (int epoch = 0; epoch < 8; epoch++)
            {
                ushort preferred = (ushort)(epoch % 2 == 0 ? 3 : 2);
                if (epoch == 2) cluster.Net.Kill(2);
                if (epoch == 3)
                {
                    await cluster.Agents[2].DisposeAsync();
                    cluster.Agents[2] = await MeshAgent.StartAsync(2, keys.Membership(), keys.Keys[2], cluster.Net.Attach(2), []);
                }
                ushort other = (ushort)(5 - preferred);
                cluster.Agents[preferred].Router.Conditions = new(500_000, .025);
                cluster.Agents[other].Router.Conditions = new(48_000, .08);
                var transfers = pairs.Select((p, index) => Task.WhenAll(
                    Verify(p.Client, p.Server, epoch * 100 + index),
                    Verify(p.Server, p.Client, 5000 + epoch * 100 + index))).ToArray();
                await Until(() => a.Router.Routes.GetValueOrDefault((ushort)4)?.NextHop == preferred, ct);
                await Task.WhenAll(transfers);
            }

            async Task Verify(MeshConnection sender, MeshConnection receiver, int seed)
            {
                var data = new byte[4096]; new Random(seed).NextBytes(data);
                await ReliableMessages.WriteAsync(sender.Stream, data, ct);
                Assert.Equal(data, await ReliableMessages.ReadAsync(receiver.Stream, ct));
            }
        }
        finally
        {
            foreach (var p in pairs) { await p.Client.DisposeAsync(); await p.Server.DisposeAsync(); }
        }
    }

    [Fact] public async Task NativeQuiclyPeersCarryAnEndToEndStreamToAnOutboundOnlyHost()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(25));
        var members = keys.Membership();
        var linkA = new QuiclyLinks(1, members, keys.Keys[1], new(IPAddress.Loopback, 0), new Dictionary<ushort, IPEndPoint>());
        await using var a = await MeshAgent.StartAsync(1, members, keys.Keys[1], linkA, [Identities.App(1)]);
        var linkB = new QuiclyLinks(2, members, keys.Keys[2], null, new Dictionary<ushort, IPEndPoint> { [1] = linkA.LocalEndPoint! });
        await using var b = await MeshAgent.StartAsync(2, members, keys.Keys[2], linkB, [Identities.App(2)]);
        await Until(() => a.Router.Routes.ContainsKey(2) && b.Router.Routes.ContainsKey(1), timeout.Token);
        await using var listener = b.Register("app").Listen(443, Identities.Prefix);
        await using var client = await a.Register("app").ConnectAsync(new(Identities.Address(2), 443), timeout.Token);
        await using var server = await listener.AcceptAsync(timeout.Token);
        await ReliableMessages.WriteAsync(client.Stream, new byte[] { 3, 1, 4 }, timeout.Token);
        Assert.Equal(new byte[] { 3, 1, 4 }, await ReliableMessages.ReadAsync(server.Stream, timeout.Token));
    }
}
