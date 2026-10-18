namespace TqkLibrary.TlsFingerCopy.Helpers;

/// <summary>
/// RFC 8701 GREASE value detection.
/// </summary>
public static class GreaseHelper
{
    /// <summary>
    /// True for 0x0a0a, 0x1a1a, ... 0xfafa.
    /// </summary>
    public static bool IsGrease(ushort value)
    {
        byte hi = (byte)(value >> 8);
        byte lo = (byte)(value & 0xff);
        return hi == lo && (hi & 0x0f) == 0x0a;
    }
}
