using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Tedd.HostMesh.Simulation;

namespace Tedd.HostMesh.Tests;

public sealed class Identities : IDisposable
{
    internal readonly X509Certificate2[] Keys = Enumerable.Range(0, 6).Select(Create).ToArray();
    internal MeshMembership Membership(params ushort[] leaves) => new(Enumerable.Range(1, 5)
        .Select(n => new Member((ushort)n, Keys[n], !leaves.Contains((ushort)n), n == 1)),
        Enumerable.Range(1, 5).ToDictionary(n => Address((ushort)n), n => (ushort)n));
    internal static IPAddress Address(ushort n) => IPAddress.Parse($"10.80.0.{n}");
    internal static System.Net.IPNetwork Prefix => System.Net.IPNetwork.Parse("10.80.0.0/24");
    internal static ApplicationGrant App(ushort n) => new("app", Address(n), [new(Prefix)], n == 1);

    private static X509Certificate2 Create(int n)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest($"CN=mesh-{n}", key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            [new Oid("1.3.6.1.5.5.7.3.1"), new Oid("1.3.6.1.5.5.7.3.2")], false));
        using var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        return X509CertificateLoader.LoadPkcs12(cert.Export(X509ContentType.Pfx), null, X509KeyStorageFlags.Exportable);
    }

    public void Dispose() { foreach (var cert in Keys) cert.Dispose(); }
}

internal sealed class Lab
{
    internal readonly SimulationClock Clock = new();
    internal readonly SimulatedNetwork Network;
    internal readonly Dictionary<ushort, MeshRouter> Nodes = [];
    internal readonly Dictionary<ushort, IMeshLinks> Ports = [];
    private readonly Identities _keys;
    private readonly MeshMembership _membership;
    private long _generation;

    internal Lab(Identities keys, int seed = 1, params ushort[] leaves)
    {
        _keys = keys;
        _membership = keys.Membership(leaves);
        Network = new(seed, Clock);
        for (ushort i = 1; i <= 4; i++) Start(i);
    }

    internal void Start(ushort id)
    {
        var links = Network.Attach(id);
        Ports[id] = links;
        Nodes[id] = new(id, _membership, _keys.Keys[id], links, Clock, id, ++_generation);
    }

    internal void Diamond()
    {
        Network.AllowDial(1, 2); Network.AllowDial(1, 3);
        Network.AllowDial(4, 2); Network.AllowDial(4, 3);
        Advance(1100);
    }

    internal void Advance(int milliseconds)
    {
        for (int t = 0; t < milliseconds; t += 10)
        {
            Clock.Advance(10);
            foreach (var n in Nodes.Values) n.Tick();
        }
    }
    internal void Kill(ushort node)
    {
        Network.Kill(node);
        Nodes.Remove(node);
    }
    internal async Task Stop(ushort node)
    {
        Nodes[node].Stop();
        Nodes.Remove(node);
        await Ports[node].DisposeAsync();
    }
}
