using System.Net;
using Tedd.HostMesh.Agent;

namespace Tedd.HostMesh.Tests;

public sealed class ConfigurationTests(Identities keys) : IClassFixture<Identities>
{
    [Fact] public void DelegatedAddressesMustHaveOneOwner()
    {
        var prefix = System.Net.IPNetwork.Parse("fd00:1::/64");
        var one = new Member(1, keys.Keys[1], Prefixes: [prefix]);
        var two = new Member(2, keys.Keys[2], Prefixes: [System.Net.IPNetwork.Parse("fd00:1::/80")]);
        Assert.Throws<ArgumentException>(() => new MeshMembership([one, two], new Dictionary<IPAddress, ushort>()));
        Assert.Throws<ArgumentException>(() => new MeshMembership([one, two with { Prefixes = null }], new Dictionary<IPAddress, ushort> { [IPAddress.Parse("fd00:1::8")] = 2 }));
        var members = new MeshMembership([one], new Dictionary<IPAddress, ushort>());
        Assert.Equal((ushort)1, members.Owner(IPAddress.Parse("fd00:1::4123")));
        Assert.Throws<ArgumentException>(() => members.Owner(IPAddress.Parse("fd00:2::4123")));
    }

    [Fact] public void DuplicateNodeCertificatesAndLocalIdentityMismatchAreRejected()
    {
        Assert.Throws<ArgumentException>(() => new MeshMembership([new(1, keys.Keys[1]), new(2, keys.Keys[1])], new Dictionary<IPAddress, ushort>()));
        var links = new Simulation.SimulatedNetwork(1).Attach(1);
        Assert.Throws<ArgumentException>(() => new MeshRouter(1, keys.Membership(), keys.Keys[3], links));
    }

    [Theory] [InlineData("10.0.3.0/29", "10.0.3.2", "10.0.3.3")] [InlineData("fd00:2::/125", "fd00:2::2", "fd00:2::3")]
    public void AddressReservationsSurviveRestartAndConfigurationReordering(string prefix, string fixedIp, string nextIp)
    {
        WithDirectory(dir =>
        {
            var pool = System.Net.IPNetwork.Parse(prefix);
            var addresses = AddressReservations.Resolve(dir, [("auto", null), ("static", fixedIp)], [pool], []);
            Assert.Equal(IPAddress.Parse(nextIp), addresses["auto"]);
            var again = AddressReservations.Resolve(dir, [("static", fixedIp), ("second", null), ("auto", null)], [pool], []);
            Assert.Equal(addresses["auto"], again["auto"]);
            Assert.Equal(3, again.Values.Distinct().Count());
            Assert.Throws<InvalidDataException>(() => AddressReservations.Resolve(dir, [("intruder", nextIp)], [pool], []));
        });
    }

    [Fact] public void ExhaustedIpv4PoolCannotAllocateTheBroadcastAddress()
    {
        WithDirectory(dir => Assert.Throws<InvalidDataException>(() => AddressReservations.Resolve(dir,
            [("one", null), ("two", null)], [System.Net.IPNetwork.Parse("192.0.2.0/30")], [])));
    }

    [Theory] [InlineData("192.0.2.5:321", "10.1.0.7:443", 0x11, 28)]
    [InlineData("[2001:db8::4]:321", "[fd00::7]:443", 0x21, 52)]
    public void ProxyV2PreambleEncodesVerifiedEndpointAndMeshDestination(string from, string to, int family, int length)
    {
        var header = SocketForwards.ProxyHeader(IPEndPoint.Parse(from), IPEndPoint.Parse(to));
        Assert.Equal(length, header.Length);
        Assert.Equal(new byte[] { 13, 10, 13, 10, 0, 13, 10, 81, 85, 73, 84, 10, 0x21 }, header[..13]);
        Assert.Equal(family, header[13]);
        Assert.Equal(length - 16, System.Buffers.Binary.BinaryPrimitives.ReadUInt16BigEndian(header.AsSpan(14)));
        Assert.Equal(IPEndPoint.Parse(from).Address.GetAddressBytes(), header[16..(16 + (length - 20) / 2)]);
        Assert.Equal(321, System.Buffers.Binary.BinaryPrimitives.ReadUInt16BigEndian(header.AsSpan(length - 4)));
        Assert.Equal(443, System.Buffers.Binary.BinaryPrimitives.ReadUInt16BigEndian(header.AsSpan(length - 2)));
    }

    [Fact] public void IdentitySignaturesAreBoundToTheirProtocolPurpose()
    {
        byte[] payload = [1, 2, 3, 4];
        var signature = IdentityProof.Sign(keys.Keys[2], ProofPurpose.Datagram, payload);
        Assert.True(IdentityProof.Verify(keys.Keys[2], ProofPurpose.Datagram, payload, signature));
        Assert.False(IdentityProof.Verify(keys.Keys[2], ProofPurpose.LinkState, payload, signature));
        Assert.False(IdentityProof.Verify(keys.Keys[1], ProofPurpose.Datagram, payload, signature));
    }

    [Fact] public void SignedPoliciesRejectTamperingAndRetainRevocationAcrossRestart()
    {
        WithDirectory(dir =>
        {
            string path = Path.Combine(dir, "policy.json");
            File.WriteAllText(path, """{"revision":1,"revokedNodes":[2]}""");
            SignedConfiguration.Sign(path, keys.Keys[1]);
            var store = new RevocationStore(dir, path, [1, 2], keys.Keys[1]);
            Assert.Equal(new ushort[] { 2 }, store.Current.RevokedNodes);
            File.WriteAllText(path, """{"revision":2,"revokedNodes":[]}""");
            Assert.Throws<InvalidDataException>(() => store.Refresh());
            Assert.Equal(1, store.Current.Revision);
            File.Delete(path);
            Assert.Equal(new ushort[] { 2 }, new RevocationStore(dir, path, [1, 2], keys.Keys[1]).Current.RevokedNodes);
            File.WriteAllText(path, """{"revision":2,"revokedNodes":[]}""");
            SignedConfiguration.Sign(path, keys.Keys[1]);
            Assert.True(store.Refresh());
            Assert.Empty(store.Current.RevokedNodes);
        });
    }

    [Fact] public void StagedCertificateCanAuthenticateAndSignForItsExistingNode()
    {
        var member = new Member(3, keys.Keys[3], RotationCertificates: [keys.Keys[5]]);
        var members = new MeshMembership([member], new Dictionary<IPAddress, ushort>());
        Assert.Equal((ushort)3, members.Identify(keys.Keys[5]));
        Assert.True(member.Verify(ProofPurpose.LinkState, [13], IdentityProof.Sign(keys.Keys[5], ProofPurpose.LinkState, [13])));
        members.Revoke([3]);
        Assert.Equal((ushort)0, members.Identify(keys.Keys[3]));
        Assert.Equal((ushort)0, members.Identify(keys.Keys[5]));
    }

    private static void WithDirectory(Action<string> test)
    {
        string root = Environment.GetEnvironmentVariable("HOSTMESH_TEST_ROOT") ??
            (OperatingSystem.IsWindows() && Directory.Exists(@"D:\Workspaces\AI") ? @"D:\Workspaces\AI\hostmesh-tests" : Path.Combine(Path.GetTempPath(), "hostmesh-tests"));
        string directory = Directory.CreateDirectory(Path.Combine(Path.GetFullPath(root), "addresses-" + Guid.NewGuid().ToString("N"))).FullName;
        try { test(directory); }
        finally
        {
            if (Path.GetDirectoryName(directory) == Path.TrimEndingDirectorySeparator(Path.GetFullPath(root)) && Path.GetFileName(directory).StartsWith("addresses-", StringComparison.Ordinal))
                Directory.Delete(directory, true);
        }
    }
}
