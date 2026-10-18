using TqkLibrary.TlsFingerCopy.Helpers;
using TqkLibrary.TlsFingerCopy.Models;

namespace TqkLibrary.TlsFingerCopy;

/// <summary>
/// Builds a <see cref="TlsFingerprint"/> from a parsed <see cref="ClientHelloInfo"/>.
/// Volatile per-connection data is sanitized in the fingerprint (the <see cref="ClientHelloInfo"/> keeps raw values):
/// key_share key exchange bytes and encrypted_client_hello payload are zeroed (lengths and group ids kept),
/// pre_shared_key and early_data extensions are dropped (see <see cref="TlsFingerprint.HadPreSharedKey"/>).
/// </summary>
public class TlsFingerprintFactory
{
    private const ushort KeyShareType = 51;
    private const ushort EncryptedClientHelloType = 0xfe0d;
    private const ushort PreSharedKeyType = 41;
    private const ushort EarlyDataType = 42;

    private readonly Ja3Calculator _ja3 = new();
    private readonly Ja4Calculator _ja4 = new();

    public TlsFingerprint Create(ClientHelloInfo info, string? name = null, string? source = null, DateTimeOffset? recordedAt = null)
    {
        ArgumentNullException.ThrowIfNull(info);
        string ja3 = _ja3.BuildString(info);
        return new TlsFingerprint
        {
            Name = name,
            Source = source,
            RecordedAt = recordedAt ?? DateTimeOffset.UtcNow,
            ServerName = info.ServerName,
            RecordVersion = info.RecordVersion,
            SessionIdLength = info.SessionId.Length,
            LegacyVersion = info.LegacyVersion,
            CipherSuites = new List<ushort>(info.CipherSuites),
            CompressionMethods = new List<byte>(info.CompressionMethods),
            Extensions = info.Extensions
                .Where(x => x.Type != PreSharedKeyType && x.Type != EarlyDataType)
                .Select(x => new TlsExtensionEntry { Type = x.Type, DataHex = Sanitize(x) })
                .ToList(),
            SupportedGroups = new List<ushort>(info.SupportedGroups),
            EcPointFormats = new List<byte>(info.EcPointFormats),
            SignatureAlgorithms = new List<ushort>(info.SignatureAlgorithms),
            Alpn = new List<string>(info.Alpn),
            SupportedVersions = new List<ushort>(info.SupportedVersions),
            KeyShareGroups = new List<ushort>(info.KeyShareGroups),
            PskKeyExchangeModes = new List<byte>(info.PskKeyExchangeModes),
            CertCompressionAlgorithms = new List<ushort>(info.CertCompressionAlgorithms),
            DelegatedCredentialSigAlgs = new List<ushort>(info.DelegatedCredentialSigAlgs),
            HasPreSharedKey = info.HasPreSharedKey,
            HadPreSharedKey = info.HasPreSharedKey || info.Extensions.Any(x => x.Type == PreSharedKeyType),
            PaddingLength = info.PaddingLength,
            HasPaddingExtension = info.PaddingLength.HasValue,
            UsesGrease = UsesGrease(info),
            ExtensionOrderRandomized = false,
            SampleCount = 1,
            Ja3 = ja3,
            Ja3Hash = _ja3.ComputeHash(ja3),
            Ja4 = _ja4.Compute(info),
            RawClientHelloHex = Convert.ToHexString(info.RawHandshake).ToLowerInvariant(),
        };
    }

    public static bool UsesGrease(ClientHelloInfo info)
        => info.CipherSuites.Any(GreaseHelper.IsGrease)
        || info.Extensions.Any(x => GreaseHelper.IsGrease(x.Type))
        || info.SupportedGroups.Any(GreaseHelper.IsGrease)
        || info.SupportedVersions.Any(GreaseHelper.IsGrease)
        || info.SignatureAlgorithms.Any(GreaseHelper.IsGrease)
        || info.KeyShareGroups.Any(GreaseHelper.IsGrease);

    private static string Sanitize(TlsExtensionEntry entry)
    {
        if (entry.Type == EncryptedClientHelloType) return SanitizeEch(entry.DataHex);
        if (entry.Type != KeyShareType) return entry.DataHex;

        byte[] data = Convert.FromHexString(entry.DataHex);
        // key_share: u16 list length, then entries of (u16 group, u16 length, key bytes). Zero the key bytes only.
        int pos = 2;
        while (pos + 4 <= data.Length)
        {
            int keyLength = (data[pos + 2] << 8) | data[pos + 3];
            pos += 4;
            int end = Math.Min(pos + keyLength, data.Length);
            if (end > pos) Array.Clear(data, pos, end - pos);
            pos = end;
        }
        return Convert.ToHexString(data).ToLowerInvariant();
    }

    /// <summary>
    /// encrypted_client_hello outer: type(1)=0, kdf_id(2), aead_id(2), config_id(1), enc&lt;u16&gt;, payload&lt;u16&gt;.
    /// Keeps the header (type, cipher suite, both lengths) and zeroes config_id, enc and payload (per-connection
    /// random); anything that does not parse as that structure is zeroed entirely.
    /// </summary>
    private static string SanitizeEch(string dataHex)
    {
        byte[] data = Convert.FromHexString(dataHex);
        const int EncLengthPos = 6;
        if (data.Length >= EncLengthPos + 2 + 2 && data[0] == 0)
        {
            int encLength = (data[EncLengthPos] << 8) | data[EncLengthPos + 1];
            int payloadLengthPos = EncLengthPos + 2 + encLength;
            if (payloadLengthPos + 2 <= data.Length)
            {
                int payloadLength = (data[payloadLengthPos] << 8) | data[payloadLengthPos + 1];
                if (payloadLength > 0 && payloadLengthPos + 2 + payloadLength == data.Length)
                {
                    data[5] = 0; // config_id
                    Array.Clear(data, EncLengthPos + 2, encLength);
                    Array.Clear(data, payloadLengthPos + 2, payloadLength);
                    return Convert.ToHexString(data).ToLowerInvariant();
                }
            }
        }
        return new string('0', dataHex.Length);
    }
}
