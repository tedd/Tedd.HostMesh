using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Tedd.HostMesh;

public sealed record Member(ushort Id, X509Certificate2 Certificate, bool Relay = true, bool Ingress = false, IReadOnlyList<System.Net.IPNetwork>? Prefixes = null, IReadOnlyList<X509Certificate2>? RotationCertificates = null)
{
    internal IEnumerable<X509Certificate2> Certificates => RotationCertificates == null ? [Certificate] : RotationCertificates.Prepend(Certificate);
    internal static bool Valid(X509Certificate2 certificate) => DateTime.UtcNow >= certificate.NotBefore.ToUniversalTime()
        && DateTime.UtcNow < certificate.NotAfter.ToUniversalTime();
    internal bool Matches(X509Certificate? peer) => peer is X509Certificate2 certificate && Valid(certificate)
        && Certificates.Any(c => certificate.RawDataMemory.Span.SequenceEqual(c.RawDataMemory.Span));
    internal bool Verify(ProofPurpose purpose, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
    {
        foreach (var cert in Certificates)
            if (Valid(cert) && IdentityProof.Verify(cert, purpose, data, signature)) return true;
        return false;
    }
}

public sealed class MeshMembership
{
    private readonly Dictionary<ushort, Member> _members;
    private readonly Dictionary<IPAddress, ushort> _owners;
    private volatile HashSet<ushort> _revoked = [];
    private long _revision;
    internal long PolicyRevision => Interlocked.Read(ref _revision);
    private readonly (System.Net.IPNetwork Prefix, ushort Owner)[] _prefixes;

    public MeshMembership(IEnumerable<Member> members, IReadOnlyDictionary<IPAddress, ushort> addresses)
    {
        _members = members.ToDictionary(member => member.Id);
        _owners = addresses.ToDictionary();
        _prefixes = _members.Values.SelectMany(m => (m.Prefixes ?? []).Select(p => (p, m.Id))).ToArray();
        for (int i = 0; i < _prefixes.Length; i++)
        {
            var (prefix, owner) = _prefixes[i];
            if (_prefixes.Take(i).Any(p => p.Prefix.Contains(prefix.BaseAddress) || prefix.Contains(p.Prefix.BaseAddress))
                || _owners.Any(p => p.Value != owner && prefix.Contains(p.Key)))
                throw new ArgumentException("Mesh address delegations overlap.");
        }
        if (_members.Count is < 1 or > 128 || _members.ContainsKey(0)
            || _members.Values.SelectMany(m => m.Certificates).GroupBy(c => c.Thumbprint).Any(group => group.Count() > 1)
            || _owners.Values.Any(id => !_members.ContainsKey(id)))
            throw new ArgumentException("Membership requires unique node identities and a known owner for every address.");
    }

    public Member this[ushort id] => _members[id];
    public bool Contains(ushort id) => _members.ContainsKey(id) && !_revoked.Contains(id);
    internal void Revoke(IEnumerable<ushort> nodes)
    {
        var next = nodes.ToHashSet();
        if (next.Any(id => !_members.ContainsKey(id))) throw new ArgumentException("Unknown node in revocation list.");
        _revoked = next;
        Interlocked.Increment(ref _revision);
    }
    public ushort Owner(IPAddress ip)
    {
        if (_owners.TryGetValue(ip, out ushort owner)) return owner;
        foreach (var delegation in _prefixes)
            if (delegation.Prefix.Contains(ip)) return delegation.Owner;
        throw new ArgumentException("Unknown mesh address.", nameof(ip));
    }
    public ushort Identify(X509Certificate? certificate) => _members.Values.FirstOrDefault(m => Contains(m.Id) && m.Matches(certificate))?.Id ?? 0;
}

public sealed record LinkConditions
{
    public long BytesPerSecond { get; }
    public double Loss { get; }
    public static LinkConditions Unlimited { get; } = new();
    public LinkConditions(long bytesPerSecond = 0, double loss = 0)
    {
        if (bytesPerSecond < 0 || bytesPerSecond > 100_000_000_000L) throw new ArgumentOutOfRangeException(nameof(bytesPerSecond));
        if (!double.IsFinite(loss) || loss is < 0 or > 1) throw new ArgumentOutOfRangeException(nameof(loss));
        BytesPerSecond = bytesPerSecond;
        Loss = loss;
    }
}

public interface IMeshLinks : IAsyncDisposable
{
    IReadOnlyList<ushort> Peers { get; }
    bool Send(ushort peer, ReadOnlySpan<byte> packet);
    bool TryReceive(out ushort peer, out byte[] packet);
}

public enum RoutingClass { Throughput, Latency }
public sealed record MeshRoute(ushort NextHop, int Hops, long Bottleneck, long DelayMilliseconds = 0);
public readonly record struct MeshCounters(long SentBytes, long SimulatedDrops, long QueueDrops, long ReceivedPackets, long ForwardedPackets, long InvalidPackets);

internal enum ProofPurpose : byte { PeerAdmission = 1, LinkState = 2, Datagram = 3 }

internal static class IdentityProof
{
    public static byte[] Sign(X509Certificate2 cert, ProofPurpose purpose, ReadOnlySpan<byte> message)
    {
        byte[] digest = Digest(purpose, message);
        using var rsa = cert.GetRSAPrivateKey();
        if (rsa != null) return rsa.SignHash(digest, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var ec = cert.GetECDsaPrivateKey() ?? throw new ArgumentException("A signing key is required.");
        return ec.SignHash(digest);
    }

    public static bool Verify(X509Certificate2 cert, ProofPurpose purpose, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature)
    {
        byte[] digest = Digest(purpose, message);
        using var rsa = cert.GetRSAPublicKey();
        if (rsa != null) return rsa.VerifyHash(digest, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var ec = cert.GetECDsaPublicKey();
        return ec?.VerifyHash(digest, signature) == true;
    }

    private static byte[] Digest(ProofPurpose purpose, ReadOnlySpan<byte> message)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData("Tedd.HostMesh/1"u8);
        hash.AppendData([(byte)purpose]);
        hash.AppendData(message);
        return hash.GetHashAndReset();
    }
}
