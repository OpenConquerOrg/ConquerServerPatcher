using System.Buffers.Binary;

namespace ConquerRsaTool.Core.Patching;

public static class ModulusCodec
{
    public const int WordCount = 64;
    public const int XorStartIndex = 17;

    public static uint[] ToWords(ReadOnlySpan<byte> modulus)
    {
        if (modulus.Length != 256) throw new InvalidDataException("El módulo RSA debe tener 256 bytes.");
        var words = new uint[WordCount];
        for (var i = 0; i < WordCount; i++)
            words[i] = BinaryPrimitives.ReadUInt32BigEndian(modulus.Slice(i * 4, 4));
        return words;
    }

    public static byte[] FromWords(IReadOnlyList<uint> words)
    {
        if (words.Count != WordCount) throw new InvalidDataException("Se esperaban 64 palabras RSA.");
        var result = new byte[256];
        for (var i = 0; i < WordCount; i++)
            BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(i * 4, 4), words[i]);
        return result;
    }

    public static uint[] Obfuscate(IReadOnlyList<uint> words)
    {
        if (words.Count != WordCount) throw new InvalidDataException("Se esperaban 64 palabras RSA.");
        var obfuscated = new uint[WordCount];
        obfuscated[63] = words[XorStartIndex - 1];
        for (var j = 62; j >= 0; j--)
            obfuscated[j] = words[(XorStartIndex + j) % WordCount] ^ obfuscated[j + 1];
        return obfuscated;
    }

    public static uint[] Deobfuscate(IReadOnlyList<uint> obfuscated)
    {
        if (obfuscated.Count != WordCount) throw new InvalidDataException("Se esperaban 64 palabras RSA ofuscadas.");
        var words = new uint[WordCount];
        var idx = XorStartIndex;
        for (var j = 0; j < 63; j++) words[idx++ % WordCount] = obfuscated[j] ^ obfuscated[j + 1];
        words[idx % WordCount] = obfuscated[63];
        return words;
    }
}
