using System.Net;
using System.Text.Json;

namespace Tedd.HostMesh.Agent;

/// <summary>Allocates application IPs within a locally delegated prefix, under the host's state-directory lock.</summary>
internal static class AddressReservations
{
    internal static Dictionary<string, IPAddress> Resolve(string directory, IEnumerable<(string Name, string? Address)> apps,
        IReadOnlyList<System.Net.IPNetwork> pools, IEnumerable<IPAddress> reserved, Func<IPAddress, bool>? owns = null)
    {
        string path = Path.Combine(directory, "addresses.json");
        var saved = File.Exists(path) ? JsonSerializer.Deserialize<Dictionary<string, string>>(File.ReadAllText(path))
            ?? throw new InvalidDataException("Invalid address reservations.") : [];
        var owners = saved.ToDictionary(p => IPAddress.Parse(p.Value), p => p.Key);
        var configured = apps.ToDictionary(p => p.Name, p => p.Address);
        var excluded = reserved.ToHashSet();
        var result = new Dictionary<string, IPAddress>(StringComparer.Ordinal);
        foreach (var (name, address) in configured.OrderBy(p => p.Value == null).ThenBy(p => p.Key, StringComparer.Ordinal))
        {
            IPAddress ip;
            if (address != null) ip = IPAddress.Parse(address);
            else if (saved.TryGetValue(name, out var prior))
            {
                ip = IPAddress.Parse(prior);
                if (!pools.Any(p => p.Contains(ip))) throw new InvalidDataException("A reserved application address falls outside the delegated pools.");
            }
            else ip = pools.SelectMany(Candidates).FirstOrDefault(c => !owners.ContainsKey(c) && !excluded.Contains(c))
                ?? throw new InvalidDataException("No free delegated application address.");
            if (owns != null && !owns(ip)) throw new InvalidDataException("Application address belongs to a different node.");
            if (owners.TryGetValue(ip, out var owner) && owner != name)
                throw new InvalidDataException("Address already reserved for a different application.");
            if (saved.TryGetValue(name, out var existing) && !IPAddress.Parse(existing).Equals(ip))
                throw new InvalidDataException("Changing an existing address requires an explicit reassignment of its reservation.");
            saved[name] = ip.ToString();
            owners[ip] = name;
            result.Add(name, ip);
        }
        string pending = path + ".next";
        using (var file = new FileStream(pending, FileMode.Create, FileAccess.Write, FileShare.None))
        {
            JsonSerializer.Serialize(file, saved); file.Flush(true);
        }
        File.Move(pending, path, true);
        return result;
    }

    private static IEnumerable<IPAddress> Candidates(System.Net.IPNetwork network)
    {
        byte[] address = network.BaseAddress.GetAddressBytes();
        int bits = address.Length * 8 - network.PrefixLength;
        long limit = bits >= 32 ? (long)uint.MaxValue + 1 : 1L << bits;
        if (address.Length == 4) limit--; // IPv4 broadcast
        for (long index = 1; index < limit; index++)
        {
            for (int j = address.Length - 1; j >= 0 && ++address[j] == 0; j--) { }
            if (index > 1) yield return new IPAddress(address); // offset one is the host address
        }
    }
}
