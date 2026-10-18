namespace TqkLibrary.TlsFingerCopy.Models;

/// <summary>
/// Serializable fingerprint file format.
/// </summary>
public class TlsFingerprint
{
    public int FormatVersion { get; set; } = 1;

    public string? Name { get; set; }

    public DateTimeOffset RecordedAt { get; set; }

    public string? ServerName { get; set; }

    /// <summary>Process / application name, free text.</summary>
    public string? Source { get; set; }

    /// <summary>Record layer version of the first record; 0 when the sample was a bare handshake message.</summary>
    public ushort RecordVersion { get; set; }

    /// <summary>Length of the session id the client sent; replay should generate a fresh id of this length.</summary>
    public int SessionIdLength { get; set; }

    public ushort LegacyVersion { get; set; }

    public List<ushort> CipherSuites { get; set; } = new();

    public List<byte> CompressionMethods { get; set; } = new();

    public List<TlsExtensionEntry> Extensions { get; set; } = new();

    public List<ushort> SupportedGroups { get; set; } = new();

    public List<byte> EcPointFormats { get; set; } = new();

    public List<ushort> SignatureAlgorithms { get; set; } = new();

    public List<string> Alpn { get; set; } = new();

    public List<ushort> SupportedVersions { get; set; } = new();

    public List<ushort> KeyShareGroups { get; set; } = new();

    public List<byte> PskKeyExchangeModes { get; set; } = new();

    public List<ushort> CertCompressionAlgorithms { get; set; } = new();

    public List<ushort> DelegatedCredentialSigAlgs { get; set; } = new();

    public bool HasPreSharedKey { get; set; }

    /// <summary>
    /// True when the sample carried a pre_shared_key (41) extension. Extensions 41 and 42 (early_data) are
    /// excluded from <see cref="Extensions"/> because they are per-connection resumption data.
    /// </summary>
    public bool HadPreSharedKey { get; set; }

    /// <summary>
    /// Informational only: length of the padding (21) extension data seen in the sample. Replay must recompute
    /// padding itself (BoringSSL rule) instead of reusing this value.
    /// </summary>
    public int? PaddingLength { get; set; }

    /// <summary>True when the sample carried a padding (21) extension.</summary>
    public bool HasPaddingExtension { get; set; }

    public bool UsesGrease { get; set; }

    public bool ExtensionOrderRandomized { get; set; }

    public int SampleCount { get; set; }

    public string Ja3 { get; set; } = string.Empty;

    public string Ja3Hash { get; set; } = string.Empty;

    public string Ja4 { get; set; } = string.Empty;

    /// <summary>
    /// Raw ClientHello handshake bytes (lowercase hex). Contains per-connection secrets (random, session id,
    /// key shares, PSK) and the hostname; do not share it publicly.
    /// </summary>
    public string RawClientHelloHex { get; set; } = string.Empty;
}
