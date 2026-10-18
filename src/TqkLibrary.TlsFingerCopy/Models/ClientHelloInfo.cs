namespace TqkLibrary.TlsFingerCopy.Models;

/// <summary>
/// A parsed TLS ClientHello.
/// </summary>
public class ClientHelloInfo
{
    /// <summary>Record layer version; 0 when parsed from a bare handshake message.</summary>
    public ushort RecordVersion { get; set; }

    public ushort LegacyVersion { get; set; }

    /// <summary>Per-connection random (32 bytes).</summary>
    public byte[] Random { get; set; } = Array.Empty<byte>();

    /// <summary>Per-connection session id.</summary>
    public byte[] SessionId { get; set; } = Array.Empty<byte>();

    /// <summary>Cipher suites in wire order, GREASE kept as actual values.</summary>
    public List<ushort> CipherSuites { get; set; } = new();

    public List<byte> CompressionMethods { get; set; } = new();

    /// <summary>Extensions in wire order.</summary>
    public List<TlsExtensionEntry> Extensions { get; set; } = new();

    public string? ServerName { get; set; }

    public List<ushort> SupportedGroups { get; set; } = new();

    public List<byte> EcPointFormats { get; set; } = new();

    public List<ushort> SignatureAlgorithms { get; set; } = new();

    public List<string> Alpn { get; set; } = new();

    /// <summary>Raw bytes of each ALPN protocol in wire order (the ASCII-decoded <see cref="Alpn"/> is lossy for non-ASCII bytes).</summary>
    public List<byte[]> AlpnRaw { get; set; } = new();

    public List<ushort> SupportedVersions { get; set; } = new();

    /// <summary>Groups offered in key_share (keys not included).</summary>
    public List<ushort> KeyShareGroups { get; set; } = new();

    public List<byte> PskKeyExchangeModes { get; set; } = new();

    public List<ushort> CertCompressionAlgorithms { get; set; } = new();

    public List<ushort> DelegatedCredentialSigAlgs { get; set; } = new();

    public bool HasPreSharedKey { get; set; }

    public int? PaddingLength { get; set; }

    /// <summary>Full handshake message including the 4-byte header.</summary>
    public byte[] RawHandshake { get; set; } = Array.Empty<byte>();
}
