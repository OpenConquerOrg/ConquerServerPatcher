using System.Numerics;

namespace ConquerRsaTool.Core.Crypto;

internal static class BigIntegerCodec
{
    public static BigInteger FromBigEndianUnsigned(ReadOnlySpan<byte> value) =>
        new(value, isUnsigned: true, isBigEndian: true);

    public static byte[] ToBigEndianUnsigned(BigInteger value, int length)
    {
        var bytes = value.ToByteArray(isUnsigned: true, isBigEndian: true);
        if (bytes.Length > length) throw new InvalidDataException("El entero RSA excede el tamaño del bloque.");
        if (bytes.Length == length) return bytes;
        var result = new byte[length];
        bytes.CopyTo(result.AsSpan(length - bytes.Length));
        return result;
    }
}
