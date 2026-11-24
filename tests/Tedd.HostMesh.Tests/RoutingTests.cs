using Tedd.HostMesh.Simulation;
namespace Tedd.HostMesh.Tests;

public sealed class RoutingTests(Identities keys) : IClassFixture<Identities>
{
    [Fact] public void OutboundOnlyLeavesCanExchangeTrafficThroughOneRelay()
    {
        var lab = new Lab(keys);
        lab.Network.AllowDial(1, 2); lab.Network.AllowDial(4, 2);
        lab.Advance(500);
        Assert.Equal((ushort)2, lab.Nodes[1].Routes[4].NextHop);
        Assert.Equal((ushort)2, lab.Nodes[4].Routes[1].NextHop);
        Assert.False(lab.Nodes[1].Routes.ContainsKey(3));
        Assert.True(lab.Nodes[4].SendPayload(1, [42]));
        lab.Advance(100);
        Assert.True(lab.Nodes[1].Incoming.TryRead(out var received));
        Assert.Equal((ushort)4, received.From);
        Assert.Equal(new byte[] { 42 }, received.Payload);
    }

    [Fact] public void ConfiguredLeafCannotBecomeTransit()
    {
        var lab = new Lab(keys, 1, 2);
        lab.Network.AllowDial(1, 2); lab.Network.AllowDial(4, 2);
        lab.Advance(500);
        Assert.False(lab.Nodes[1].Routes.ContainsKey(4));
        Assert.True(lab.Nodes[1].Routes.ContainsKey(2));
    }

    [Theory]
    [InlineData(2, 3)] [InlineData(3, 2)]
    public void BandwidthChangeSwitchesEstablishedForwarding(int slow, int fast)
    {
        var lab = new Lab(keys);
        lab.Diamond();
        lab.Nodes[(ushort)slow].Conditions = new(40_000);
        lab.Advance(300);
        Assert.Equal((ushort)fast, lab.Nodes[1].Routes[4].NextHop);
        lab.Nodes[(ushort)fast].Conditions = new(10_000);
        lab.Advance(300);
        Assert.Equal((ushort)slow, lab.Nodes[1].Routes[4].NextHop);
        Assert.Equal(40_000, lab.Nodes[1].Routes[4].Bottleneck);
    }

    [Fact] public void DirectionalCapacityProducesDifferentReturnPath()
    {
        var lab = new Lab(keys);
        lab.Network.Configure(2, 4, new(new(100_000)));
        lab.Network.Configure(3, 1, new(new(100_000)));
        lab.Diamond();
        Assert.Equal((ushort)3, lab.Nodes[1].Routes[4].NextHop);
        Assert.Equal((ushort)2, lab.Nodes[4].Routes[1].NextHop);
    }

    [Fact] public async Task GracefulWithdrawalPrecedesHeartbeatExpiry()
    {
        var lab = new Lab(keys);
        lab.Diamond();
        await lab.Stop(2);
        lab.Advance(60);
        Assert.Equal((ushort)3, lab.Nodes[1].Routes[4].NextHop);
    }

    [Fact] public void CrashIsSilentUntilNeighborExpiresThenRejoinConverges()
    {
        var lab = new Lab(keys);
        lab.Diamond();
        lab.Kill(2);
        lab.Advance(200);
        Assert.Equal((ushort)2, lab.Nodes[1].Routes[4].NextHop);
        lab.Advance(1500);
        Assert.Equal((ushort)3, lab.Nodes[1].Routes[4].NextHop);
        lab.Start(2);
        lab.Advance(1400);
        Assert.Equal((ushort)2, lab.Nodes[1].Routes[4].NextHop);
    }

    [Fact] public void OneWayBlackHoleInvalidatesBothDirections()
    {
        var lab = new Lab(keys);
        lab.Diamond();
        lab.Network.Configure(1, 2, new(new(loss: 1)));
        lab.Advance(2000);
        Assert.Equal((ushort)3, lab.Nodes[1].Routes[4].NextHop);
        lab.Network.Configure(1, 2, new(LinkConditions.Unlimited));
        lab.Advance(1500);
        Assert.Equal((ushort)2, lab.Nodes[1].Routes[4].NextHop);
    }

    [Theory]
    [InlineData(5)] [InlineData(27)] [InlineData(114)] [InlineData(352)] [InlineData(901)]
    public void LossDuplicationAndJitterConvergeAfterRepeatedPartitions(int seed)
    {
        var lab = new Lab(keys, seed);
        lab.Diamond();
        var rng = new Random(seed);
        for (int trial = 0; trial < 8; trial++)
        {
            ushort relay = (ushort)rng.Next(2, 4);
            lab.Network.Configure(1, relay, new(new(loss: 1)));
            lab.Network.Configure((ushort)(5 - relay), 4, new(new(loss: .12), 5, 25, .15));
            lab.Advance(2200);
            Assert.Equal((ushort)(5 - relay), lab.Nodes[1].Routes[4].NextHop);
            lab.Network.Configure(1, relay, new(LinkConditions.Unlimited));
            lab.Advance(2000);
        }
    }

    [Fact] public void RateLimitIsAggregateAcrossPeersAndTakesEffectLive()
    {
        var lab = new Lab(keys);
        lab.Diamond();
        var node = lab.Nodes[1];
        node.Conditions = new(6000);
        long before = node.Counters.SentBytes;
        for (int i = 0; i < 100; i++) node.SendPayload((ushort)(i % 2 + 2), new byte[700]);
        lab.Advance(1000);
        Assert.InRange(node.Counters.SentBytes - before, 3500, 7400);
        node.Conditions = LinkConditions.Unlimited;
        lab.Advance(40);
        Assert.True(node.Counters.SentBytes - before > 60_000);
    }

    [Fact] public void FullLossDropsTrafficUntilChangedLive()
    {
        var lab = new Lab(keys);
        lab.Diamond();
        lab.Nodes[1].Conditions = new(loss: 1);
        lab.Nodes[1].SendPayload(4, [37]);
        lab.Advance(100);
        Assert.False(lab.Nodes[4].Incoming.TryRead(out _));
        Assert.True(lab.Nodes[1].Counters.SimulatedDrops > 0);
        lab.Nodes[1].Conditions = LinkConditions.Unlimited;
        lab.Nodes[1].SendPayload(4, [38]);
        lab.Advance(100);
        Assert.True(lab.Nodes[4].Incoming.TryRead(out var item));
        Assert.Equal(38, item.Payload[0]);
    }

    [Fact] public void ParallelWritersAndLiveConfigurationMaintainPacketBoundaries()
    {
        var lab = new Lab(keys);
        lab.Diamond();
        var node = lab.Nodes[1];
        Parallel.For(0, 500, i =>
        {
            node.Conditions = new(1_000_000 + i);
            Assert.True(node.SendPayload(4, BitConverter.GetBytes(i)));
            if ((i & 7) == 0) node.Tick();
            _ = node.Routes;
        });
        lab.Advance(500);
        var values = new HashSet<int>();
        while (lab.Nodes[4].Incoming.TryRead(out var p)) Assert.True(values.Add(BitConverter.ToInt32(p.Payload)));
        Assert.Equal(500, values.Count);
    }

    [Fact] public void AnUnsignedWithdrawalCannotOverrideCurrentTopology()
    {
        var lab = new Lab(keys);
        lab.Diamond();
        var bogus = new byte[90];
        bogus[0] = 2; bogus[2] = 4; bogus[3] = 127;
        lab.Ports[2].Send(1, bogus);
        lab.Advance(50);
        Assert.True(lab.Nodes[1].Counters.InvalidPackets > 0);
        Assert.True(lab.Nodes[1].Routes.ContainsKey(4));
    }

    [Fact] public void ReplayingAnOlderSignedAdvertisementCannotUndoAGracefulWithdrawal()
    {
        var lab = new Lab(keys);
        lab.Diamond();
        lab.Nodes[2].Conditions = new(100_000_000);
        lab.Nodes[2].Tick();
        lab.Clock.Advance(10);
        byte[]? previous = null;
        while (lab.Ports[1].TryReceive(out var origin, out var packet))
            if (origin == 2 && packet.Length > 20 && packet[0] == 2 && packet[2] == 2) previous = packet;
        Assert.NotNull(previous);
        lab.Nodes[2].Stop();
        lab.Advance(80);
        Assert.Equal((ushort)3, lab.Nodes[1].Routes[4].NextHop);
        Assert.True(lab.Ports[2].Send(1, previous));
        lab.Advance(50);
        Assert.Equal((ushort)3, lab.Nodes[1].Routes[4].NextHop);
    }

    [Fact] public void IndependentSimulationsReplayTheSameSeededPacketSchedule()
    {
        static byte[] Trace(Identities keys, int seed)
        {
            var lab = new Lab(keys, seed); lab.Diamond();
            lab.Network.Configure(1, 2, new(new(loss: .32), 5, 40, .15));
            for (byte id = 0; id < 120; id++) lab.Nodes[1].SendPayload(2, [id]);
            lab.Advance(300);
            var observed = new List<byte>();
            while (lab.Nodes[2].Incoming.TryRead(out var p)) observed.Add(p.Payload[0]);
            return observed.ToArray();
        }
        var first = Trace(keys, 44);
        Assert.NotEmpty(first);
        Assert.Equal(first, Trace(keys, 44));
        Assert.False(first.SequenceEqual(Trace(keys, 45)));
    }

    [Theory] [InlineData(-1.0)] [InlineData(1.01)] [InlineData(double.NaN)] [InlineData(double.PositiveInfinity)]
    public void InvalidLiveLossIsRejected(double value) => Assert.Throws<ArgumentOutOfRangeException>(() => new LinkConditions(loss: value));
}
