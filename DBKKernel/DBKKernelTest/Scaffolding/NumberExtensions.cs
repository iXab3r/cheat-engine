namespace PoeShared.Scaffolding;

public static class NumberExtensions
{
    public static string ToHexadecimal(this long value)
    {
        return $"0x{value:X8}";
    }
    
    public static string ToHexadecimal(this ulong value)
    {
        return $"0x{value:X8}";
    }
        
    public static string ToHexadecimal(this int value)
    {
        return ToHexadecimal((long)value);
    }
        
    public static string ToHexadecimal(this uint value)
    {
        return ToHexadecimal((long)value);
    }
        
    public static string ToHexadecimal(this ushort value)
    {
        return ToHexadecimal((long)value);
    }
}