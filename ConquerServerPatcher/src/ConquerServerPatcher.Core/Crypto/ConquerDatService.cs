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
        {
            throw new InvalidDataException(
                "The file does not contain complete 256-byte RSA blocks. " +
                "This DAT file may use a different encryption method.");
        }

        using var compressed = new MemoryStream();
        for (var offset = 0; offset < encrypted.Length; offset += RsaBlockSize)
        {
            var cipher = BigIntegerCodec.FromBigEndianUnsigned(
                encrypted.AsSpan(offset, RsaBlockSize));
            var padded = BigIntegerCodec.ToBigEndianUnsigned(
                BigInteger.ModPow(cipher, PublicExponent, modulus),
                RsaBlockSize);
            var dataOffset = FindPayloadOffset(padded, offset / RsaBlockSize);
            compressed.Write(padded, dataOffset, padded.Length - dataOffset);
        }

        var payload = compressed.ToArray();
        if (payload.Length < 2 || payload[0] != 0x1F || payload[1] != 0x8B)
        {
            throw new InvalidDataException(
                "The RSA output does not contain GZip data. Make sure the selected " +
                "original Conquer.exe belongs to this DAT file and that the file uses RSA encryption.");
        }

        using var compressedInput = new MemoryStream(payload);
        using var gzip = new GZipStream(compressedInput, CompressionMode.Decompress);
        using var plain = new MemoryStream();
        try
        {
            gzip.CopyTo(plain);
        }
        catch (InvalidDataException ex)
        {
            throw new InvalidDataException(
                "The RSA blocks were decrypted, but the GZip payload is damaged " +
                "or uses a different format.",
                ex);
        }

        EnsureParent(outputPath);
        File.WriteAllBytes(outputPath, plain.ToArray());
    }

    public void Encrypt(string plainPath, string privateKeyPath, string outputPath)
    {
        var key = _keys.LoadPrivate(privateKeyPath);
        if (key.D is null || key.Modulus is null)
            throw new InvalidDataException(
                "The PEM key does not contain private parameters.");

        var privateExponent = BigIntegerCodec.FromBigEndianUnsigned(key.D);
        var modulus = BigIntegerCodec.FromBigEndianUnsigned(key.Modulus);
        var plain = File.ReadAllBytes(plainPath);

        using var compressed = new MemoryStream();
        using (var gzip = new GZipStream(
                   compressed,
                   CompressionLevel.Optimal,
                   leaveOpen: true))
        {
            gzip.Write(plain);
        }

        var payload = compressed.ToArray();
        EnsureParent(outputPath);
        using var output = File.Create(outputPath);
        for (var offset = 0; offset < payload.Length; offset += PlainChunkSize)
        {
            var size = Math.Min(PlainChunkSize, payload.Length - offset);
            var padded = CreateType1PaddedBlock(payload.AsSpan(offset, size));
            var message = BigIntegerCodec.FromBigEndianUnsigned(padded);
            var cipher = BigIntegerCodec.ToBigEndianUnsigned(
                BigInteger.ModPow(message, privateExponent, modulus),
                RsaBlockSize);
            output.Write(cipher);
        }
    }

    private static byte[] CreateType1PaddedBlock(ReadOnlySpan<byte> chunk)
    {
        if (chunk.Length > PlainChunkSize)
            throw new ArgumentOutOfRangeException(nameof(chunk));

        var result = new byte[RsaBlockSize];
        result[0] = 0;
        result[1] = 1;
        var paddingLength = RsaBlockSize - 3 - chunk.Length;
        result.AsSpan(2, paddingLength).Fill(0xFF);
        result[2 + paddingLength] = 0;
        chunk.CopyTo(result.AsSpan(3 + paddingLength));
        return result;
    }

    private static int FindPayloadOffset(byte[] block, int blockIndex)
    {
        var separator = Array.IndexOf(block, (byte)0, 2);
        if (separator < 0)
        {
            throw new InvalidDataException(
                $"The end of the RSA padding was not found in block {blockIndex + 1}. " +
                "The client key does not match this file.");
        }

        // Match the original script: discard bytes through the first 00 byte
        // starting at position 2, without requiring canonical PKCS#1 padding.
        return separator + 1;
    }

    private static void EnsureParent(string path)
    {
        var directory = Path.GetDirectoryName(Path.GetFullPath(path));
        if (!string.IsNullOrEmpty(directory))
            Directory.CreateDirectory(directory);
    }
}
