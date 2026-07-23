using System.IO.Compression;
using System.Numerics;
using System.Security.Cryptography;

namespace ConquerRsaTool.Core.Crypto;

public sealed class ConquerDatService
{
    public const int RsaBlockSize = 256;
    public const int PlainChunkSize = 245;
    private static readonly BigInteger PublicExponent = new(65537);
    private readonly RsaKeyService _keys = new();

    public void Decrypt(string encryptedPath, string publicKeyPath, string outputPath)
    {
        var key = _keys.LoadPublic(publicKeyPath);
        var modulus = BigIntegerCodec.FromBigEndianUnsigned(key.Modulus!);
        var encrypted = File.ReadAllBytes(encryptedPath);
        if (encrypted.Length == 0 || encrypted.Length % RsaBlockSize != 0)
            throw new InvalidDataException("El archivo cifrado no contiene bloques RSA completos de 256 bytes.");

        using var compressed = new MemoryStream();
        for (var offset = 0; offset < encrypted.Length; offset += RsaBlockSize)
        {
            var c = BigIntegerCodec.FromBigEndianUnsigned(encrypted.AsSpan(offset, RsaBlockSize));
            var padded = BigIntegerCodec.ToBigEndianUnsigned(BigInteger.ModPow(c, PublicExponent, modulus), RsaBlockSize);
            ValidateType1Padding(padded, out var dataOffset);
            compressed.Write(padded, dataOffset, padded.Length - dataOffset);
        }

        compressed.Position = 0;
        EnsureParent(outputPath);
        using var gzip = new GZipStream(compressed, CompressionMode.Decompress);
        using var output = File.Create(outputPath);
        gzip.CopyTo(output);
    }

    public void Encrypt(string plainPath, string privateKeyPath, string outputPath)
    {
        var key = _keys.LoadPrivate(privateKeyPath);
        if (key.D is null || key.Modulus is null) throw new InvalidDataException("La clave PEM no contiene parámetros privados.");
        var d = BigIntegerCodec.FromBigEndianUnsigned(key.D);
        var modulus = BigIntegerCodec.FromBigEndianUnsigned(key.Modulus);
        var plain = File.ReadAllBytes(plainPath);

        using var compressed = new MemoryStream();
        using (var gzip = new GZipStream(compressed, CompressionLevel.Optimal, leaveOpen: true))
            gzip.Write(plain);

        var payload = compressed.ToArray();
        EnsureParent(outputPath);
        using var output = File.Create(outputPath);
        for (var offset = 0; offset < payload.Length; offset += PlainChunkSize)
        {
            var size = Math.Min(PlainChunkSize, payload.Length - offset);
            var padded = CreateType1PaddedBlock(payload.AsSpan(offset, size));
            var m = BigIntegerCodec.FromBigEndianUnsigned(padded);
            var cipher = BigIntegerCodec.ToBigEndianUnsigned(BigInteger.ModPow(m, d, modulus), RsaBlockSize);
            output.Write(cipher);
        }
    }

    private static byte[] CreateType1PaddedBlock(ReadOnlySpan<byte> chunk)
    {
        if (chunk.Length > PlainChunkSize) throw new ArgumentOutOfRangeException(nameof(chunk));
        var result = new byte[RsaBlockSize];
        result[0] = 0;
        result[1] = 1;
        var paddingLength = RsaBlockSize - 3 - chunk.Length;
        result.AsSpan(2, paddingLength).Fill(0xFF);
        result[2 + paddingLength] = 0;
        chunk.CopyTo(result.AsSpan(3 + paddingLength));
        return result;
    }

    private static void ValidateType1Padding(byte[] block, out int dataOffset)
    {
        if (block.Length != RsaBlockSize || block[0] != 0 || block[1] != 1)
            throw new InvalidDataException("Padding PKCS#1 tipo 1 inválido.");
        var separator = Array.IndexOf(block, (byte)0, 2);
        if (separator < 10) throw new InvalidDataException("Bloque RSA con padding insuficiente.");
        for (var i = 2; i < separator; i++)
            if (block[i] != 0xFF) throw new InvalidDataException("Padding PKCS#1 corrupto.");
        dataOffset = separator + 1;
    }

    private static void EnsureParent(string path)
    {
        var dir = Path.GetDirectoryName(Path.GetFullPath(path));
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
    }
}
