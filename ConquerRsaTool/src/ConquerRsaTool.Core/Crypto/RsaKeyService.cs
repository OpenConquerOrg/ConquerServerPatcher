using System.Security.Cryptography;

namespace ConquerRsaTool.Core.Crypto;

public sealed class RsaKeyService
{
    public void GenerateKeyPair(string publicKeyPath, string privateKeyPath)
    {
        EnsureParent(publicKeyPath);
        EnsureParent(privateKeyPath);
        using var rsa = RSA.Create(2048);
        File.WriteAllText(publicKeyPath, rsa.ExportSubjectPublicKeyPem());
        File.WriteAllText(privateKeyPath, rsa.ExportPkcs8PrivateKeyPem());
    }

    public RSAParameters LoadPublic(string path)
    {
        using var rsa = RSA.Create();
        rsa.ImportFromPem(File.ReadAllText(path));
        if (rsa.KeySize != 2048) throw new InvalidDataException("La clave pública debe ser RSA de 2048 bits.");
        return rsa.ExportParameters(false);
    }

    public RSAParameters LoadPrivate(string path)
    {
        using var rsa = RSA.Create();
        rsa.ImportFromPem(File.ReadAllText(path));
        if (rsa.KeySize != 2048) throw new InvalidDataException("La clave privada debe ser RSA de 2048 bits.");
        return rsa.ExportParameters(true);
    }

    public void SavePublicModulus(byte[] modulus, string outputPath)
    {
        EnsureParent(outputPath);
        using var rsa = RSA.Create();
        rsa.ImportParameters(new RSAParameters { Modulus = modulus, Exponent = [0x01, 0x00, 0x01] });
        File.WriteAllText(outputPath, rsa.ExportSubjectPublicKeyPem());
    }

    private static void EnsureParent(string path)
    {
        var dir = Path.GetDirectoryName(Path.GetFullPath(path));
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
    }
}
