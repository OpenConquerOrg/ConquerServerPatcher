using System.Buffers.Binary;
using ConquerRsaTool.Core.Crypto;

namespace ConquerRsaTool.Core.Patching;

public sealed class ConquerBinaryService
{
    private const uint StartOriginalModulus = 0xA0AF3D5C;
    private const uint EndOriginalModulus = 0x2220F2A7;
    private readonly RsaKeyService _keys = new();

    public ClientAnalysis Analyze(string exePath)
    {
        try
        {
            var data = File.ReadAllBytes(exePath);
            var offsets = FindModulusOffsets(data, out var contiguous);
            return new(
                true,
                $"RSA modulus located successfully ({offsets.Count}/64 words).",
                offsets,
                contiguous);
        }
        catch (Exception ex)
        {
            return new(false, ex.Message, Array.Empty<int>(), false);
        }
    }

    public bool IsPatchedWithPublicKey(string exePath, string publicKeyPath)
    {
        var data = File.ReadAllBytes(exePath);
        var publicKey = _keys.LoadPublic(publicKeyPath);
        var expectedWords = ModulusCodec.Obfuscate(
            ModulusCodec.ToWords(publicKey.Modulus!));

        try
        {
            var offsets = FindModulusOffsets(
                data,
                expectedWords[0],
                expectedWords[^1],
                out _);

            for (var i = 0; i < expectedWords.Length; i++)
            {
                var actual = BinaryPrimitives.ReadUInt32LittleEndian(
                    data.AsSpan(offsets[i], sizeof(uint)));
                if (actual != expectedWords[i])
                    return false;
            }

            return true;
        }
        catch (InvalidDataException)
        {
            return false;
        }
    }

    public void ExtractPublicKey(string exePath, string outputPem)
    {
        var data = File.ReadAllBytes(exePath);
        var offsets = FindModulusOffsets(data, out _);
        var obfuscated = offsets.Select(x => BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(x, 4))).ToArray();
        var modulus = ModulusCodec.FromWords(ModulusCodec.Deobfuscate(obfuscated));
        _keys.SavePublicModulus(modulus, outputPem);
    }

    public PatchResult Patch(string exePath, string publicKeyPath, string outputPath, bool bypassPlayExe, bool createBackup = true)
    {
        var data = File.ReadAllBytes(exePath);
        var offsets = FindModulusOffsets(data, out _);
        var publicKey = _keys.LoadPublic(publicKeyPath);
        var obfuscated = ModulusCodec.Obfuscate(ModulusCodec.ToWords(publicKey.Modulus!));
        for (var i = 0; i < 64; i++) BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(offsets[i], 4), obfuscated[i]);

        var bypassApplied = false;
        var bypassMessage = "Not requested.";
        if (bypassPlayExe) (bypassApplied, bypassMessage) = PatchPlayExeBypass(data);

        EnsureParent(outputPath);
        if (createBackup && File.Exists(outputPath))
            File.Copy(outputPath, outputPath + ".bak-" + DateTime.Now.ToString("yyyyMMdd-HHmmss"), false);
        File.WriteAllBytes(outputPath, data);
        return new(outputPath, bypassApplied, bypassMessage);
    }

    public IReadOnlyList<int> FindModulusOffsets(ReadOnlySpan<byte> data, out bool contiguous)
        => FindModulusOffsets(
            data,
            StartOriginalModulus,
            EndOriginalModulus,
            out contiguous);

    private static IReadOnlyList<int> FindModulusOffsets(
        ReadOnlySpan<byte> data,
        uint startWord,
        uint endWord,
        out bool contiguous)
    {
        Span<byte> start = stackalloc byte[4];
        Span<byte> end = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(start, startWord);
        BinaryPrimitives.WriteUInt32LittleEndian(end, endWord);
        var searchFrom = 0;
        while (searchFrom <= data.Length - 4)
        {
            var relative = data[searchFrom..].IndexOf(start);
            if (relative < 0) break;
            var offset = searchFrom + relative;
            if (offset + 256 <= data.Length && data.Slice(offset + 63 * 4, 4).SequenceEqual(end))
            {
                contiguous = true;
                return Enumerable.Range(0, 64).Select(i => offset + i * 4).ToArray();
            }

            var offsets = new List<int>(64) { offset };
            int? endOffset = null;
            try
            {
                for (var i = 0; i < 63; i++)
                {
                    var next = GetNextOffset(data, offsets[^1]);
                    if (next + 4 <= data.Length &&
                        data.Slice(next, 4).SequenceEqual(end) &&
                        endOffset is null)
                    {
                        endOffset = next;
                        next = SkipJunkInstructions(data, next + 4);
                    }
                    offsets.Add(next);
                }
                if (endOffset.HasValue) offsets[^1] = endOffset.Value;
                if (offsets[^1] + 4 <= data.Length && data.Slice(offsets[^1], 4).SequenceEqual(end))
                {
                    contiguous = false;
                    return offsets;
                }
            }
            catch (InvalidDataException) { }
            searchFrom = offset + 1;
        }
        throw new InvalidDataException(
            "The original RSA modulus was not found. " +
            "The client is unsupported or has already been patched.");
    }

    private static int GetNextOffset(ReadOnlySpan<byte> data, int pos)
    {
        if (pos + 6 > data.Length)
            throw new InvalidDataException(
                "Unexpected end of file while reading instructions.");
        if (data[pos + 4] == 0xC7 && data[pos + 5] == 0x85) return pos + 10;
        if (data[pos + 4] == 0xC7 && data[pos + 5] == 0x45) return pos + 7;
        if (data[pos + 4] is >= 0xB8 and <= 0xBF) return pos + 5;
        return pos + 4;
    }

    private static int SkipJunkInstructions(ReadOnlySpan<byte> data, int pos)
    {
        while (pos + 2 <= data.Length)
        {
            if (data[pos] == 0xC7 && data[pos + 1] == 0x85) return pos + 6;
            if (data[pos] == 0xC7 && data[pos + 1] == 0x45) return pos + 3;
            if (data[pos] is >= 0xB8 and <= 0xBF) return pos + 1;
            pos++;
        }
        throw new InvalidDataException(
            "The instruction scan could not continue.");
    }

    private static (bool, string) PatchPlayExeBypass(byte[] data)
    {
        var argc = new[]
        {
            (BinaryPattern.Parse("83 F8 05 0F 94 C1 83 F8 01 88 0D ?? ?? ?? ?? 7D"), 1, new byte[]{0xEB}),
            (BinaryPattern.Parse("83 BD ?? ?? FF FF 01 0F 8D"), 2, new byte[]{0x90,0xE9}),
            (BinaryPattern.Parse("83 C4 14 83 F8 01 7C"), 1, new byte[]{0x90,0x90})
        };
        var patch1 = false;
        foreach (var (pattern, fromEnd, replacement) in argc)
        {
            var pos = pattern.Find(data);
            if (pos < 0) continue;
            replacement.CopyTo(data, pos + pattern.Bytes.Length - fromEnd);
            patch1 = true; break;
        }

        var blacknull = new[]
        {
            BinaryPattern.Parse("61 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 59 59 85 C0"),
            BinaryPattern.Parse("8D 45 1C 68 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 59 59 85 C0"),
            BinaryPattern.Parse("83 F8 01 7C ?? 8D 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 59 85 C0")
        };
        var patch2 = false;
        foreach (var pattern in blacknull)
        {
            var pos = pattern.Find(data);
            if (pos < 0) continue;
            data[pos + pattern.Bytes.Length - 2] = 0x31;
            patch2 = true; break;
        }
        return patch1 && patch2
            ? (true, "Both play.exe bypass patches were applied successfully.")
            : (false,
                $"Incomplete bypass: argc check={(patch1 ? "OK" : "not found")}, " +
                $"blacknull={(patch2 ? "OK" : "not found")}. " +
                "The RSA patch was still applied.");
    }

    private static void EnsureParent(string path)
    {
        var dir = Path.GetDirectoryName(Path.GetFullPath(path));
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
    }
}
