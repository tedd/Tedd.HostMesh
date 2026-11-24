using System.Text.Json;
using System.Security.Cryptography.X509Certificates;

namespace Tedd.HostMesh.Agent;

internal sealed record RevocationPolicy(long Revision, ushort[] RevokedNodes);

/// <summary>Persists the highest accepted local policy revision to fence stale updates after a restart.</summary>
internal sealed class RevocationStore
{
    private readonly string _statePath;
    private readonly string? _source;
    private readonly HashSet<ushort> _members;
    private readonly X509Certificate2? _authority;
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    internal RevocationPolicy Current { get; private set; } = new(0, []);

    internal RevocationStore(string directory, string? source, IEnumerable<ushort> members, X509Certificate2? authority = null)
    {
        _authority = authority;
        _members = members.ToHashSet();
        _statePath = Path.Combine(directory, "revocations.json");
        _source = source;
        if (File.Exists(_statePath)) Current = Read(_statePath);
        Refresh();
    }

    internal bool Refresh()
    {
        if (_source == null || !File.Exists(_source)) return false;
        var next = Read(_source, _authority);
        if (next.Revision <= Current.Revision) return false;
        string pending = _statePath + ".next";
        using (var stream = new FileStream(pending, FileMode.Create, FileAccess.Write, FileShare.None))
        {
            JsonSerializer.Serialize(stream, next, Json); stream.Flush(true);
        }
        File.Move(pending, _statePath, true);
        Current = next;
        return true;
    }

    private RevocationPolicy Read(string file, X509Certificate2? authority = null)
    {
        var value = JsonSerializer.Deserialize<RevocationPolicy>(SignedConfiguration.Read(file, authority), Json);
        if (value == null || value.Revision <= 0 || value.RevokedNodes == null || value.RevokedNodes.Any(id => !_members.Contains(id)))
            throw new InvalidDataException("Invalid revocation policy.");
        return value;
    }
}
