using System.Security.Cryptography;

namespace ConquerRsaTool.Core.Crypto;

public sealed class RsaKeyService
{
    public void GenerateKeyPair(string publicKeyPath, string privateKeyPath)
    {
        EnsureParent(publicKeyPath);
        EnsureParent(privateKeyPath);
        using var rsa = RSA.Create(2048);
        File.WriteAllText(publicKeyPath, rsa.ExportSubjectPublicKeyInfoPem());
        File.WriteAllText(privateKeyPath, rsa.ExportPkcs8PrivateKeyPem());
    }

    public RSAParameters LoadPublic(string path)
    {
        using var rsa = RSA.Create();
        rsa.ImportFromPem(File.ReadAllText(path));
        if (rsa.KeySize != 2048)
            throw new InvalidDataException("The public key must be a 2048-bit RSA key.");
        return rsa.ExportParameters(false);
    }

    public RSAParameters LoadPrivate(string path)
    {
        using var rsa = RSA.Create();
        rsa.ImportFromPem(File.ReadAllText(path));
        if (rsa.KeySize != 2048)
            throw new InvalidDataException("The private key must be a 2048-bit RSA key.");
        return rsa.ExportParameters(true);
    }

    public void SavePublicModulus(byte[] modulus, string outputPath)
    {
        EnsureParent(outputPath);
        using var rsa = RSA.Create();
        rsa.ImportParameters(new RSAParameters { Modulus = modulus, Exponent = [0x01, 0x00, 0x01] });
        File.WriteAllText(outputPath, rsa.ExportSubjectPublicKeyInfoPem());
    }

    private static void EnsureParent(string path)
    {
        var dir = Path.GetDirectoryName(Path.GetFullPath(path));
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
    }
}
