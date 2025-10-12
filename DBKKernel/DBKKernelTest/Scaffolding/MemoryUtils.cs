using System;
using System.Text;

namespace EyeAuras.Memory.Scaffolding;

public static class MemoryUtils
{
    public static string ReadNullTerminatedString(ReadOnlySpan<byte> span)
    {
        return ReadNullTerminatedString(span, Encoding.ASCII);
    }
    
    public static string ReadNullTerminatedStringU(ReadOnlySpan<byte> span)
    {
        return ReadNullTerminatedString(span, Encoding.UTF8);
    }
    
    public static string ReadNullTerminatedString(ReadOnlySpan<byte> span, Encoding encoding)
    {
        var nullIndex = span.IndexOf((byte) 0);
        return encoding.GetString((nullIndex >= 0 ? span.Slice(0, nullIndex) : span).ToArray());
    }
}