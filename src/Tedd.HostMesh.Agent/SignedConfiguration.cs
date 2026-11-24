using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Tedd.HostMesh.Agent;

internal static class SignedConfiguration
{
    internal static byte[] Read(string file, X509Certificate2? authority)
    {
        byte[] body = File.ReadAllBytes(file);
        if (authority == null) return body;
        byte[] signature = File.ReadAllBytes(file + ".sig");
        using var rsa = authority.GetRSAPublicKey();
        using var ec = authority.GetECDsaPublicKey();
        bool valid = rsa?.VerifyData(body, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss)
            ?? ec?.VerifyData(body, signature, HashAlgorithmName.SHA256) ?? false;
        if (!valid || DateTime.UtcNow < authority.NotBefore.ToUniversalTime() || DateTime.UtcNow >= authority.NotAfter.ToUniversalTime())
            throw new InvalidDataException("Configuration signature or authority validity check failed.");
        return body;
    }

    internal static void Sign(string file, X509Certificate2 key)
    {
        byte[] body = File.ReadAllBytes(file);
        using var rsa = key.GetRSAPrivateKey();
        using var ec = key.GetECDsaPrivateKey();
        byte[] signature = rsa?.SignData(body, HashAlgorithmName.SHA256, RSASignaturePadding.Pss)
            ?? ec?.SignData(body, HashAlgorithmName.SHA256) ?? throw new InvalidDataException("Authority signing key is missing.");
        string final = file + ".sig";
        string pending = final + "." + Guid.NewGuid().ToString("N") + ".next";
        try { File.WriteAllBytes(pending, signature); File.Move(pending, final, true); }
        finally { File.Delete(pending); }
    }
}
