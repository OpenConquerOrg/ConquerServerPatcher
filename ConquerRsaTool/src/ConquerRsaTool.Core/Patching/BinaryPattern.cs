namespace ConquerRsaTool.Core.Patching;

internal sealed record BinaryPattern(byte?[] Bytes)
{
    public static BinaryPattern Parse(string pattern) => new(pattern.Split(' ', StringSplitOptions.RemoveEmptyEntries)
        .Select(x => x is "??" or "?" ? (byte?)null : Convert.ToByte(x, 16)).ToArray());

    public int Find(ReadOnlySpan<byte> data)
    {
        for (var i = 0; i <= data.Length - Bytes.Length; i++)
        {
            var ok = true;
            for (var j = 0; j < Bytes.Length; j++)
                if (Bytes[j].HasValue && data[i + j] != Bytes[j]!.Value) { ok = false; break; }
            if (ok) return i;
        }
        return -1;
    }
}
