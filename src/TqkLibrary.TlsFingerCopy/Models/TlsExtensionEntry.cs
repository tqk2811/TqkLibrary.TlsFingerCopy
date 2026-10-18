namespace TqkLibrary.TlsFingerCopy.Models;

/// <summary>
/// One TLS extension as seen on the wire: type and raw data (lowercase hex).
/// </summary>
public class TlsExtensionEntry
{
    public ushort Type { get; set; }

    public string DataHex { get; set; } = string.Empty;
}
