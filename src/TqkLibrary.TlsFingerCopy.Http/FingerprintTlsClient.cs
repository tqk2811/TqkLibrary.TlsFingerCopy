using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using TqkLibrary.TlsFingerCopy.Models;

namespace TqkLibrary.TlsFingerCopy.Http;

/// <summary>
/// BC TLS client whose ClientHello reproduces a recorded <see cref="TlsFingerprint"/>.
/// One instance serves exactly one connection: GREASE values, ECH GREASE payload and (when the fingerprint is
/// randomized) the extension order are drawn when the instance is created.
/// </summary>
/// <remarks>
/// <para>No session is ever resumed (no session id resumption, no PSK), so pre_shared_key / early_data are never sent.</para>
/// <para>renegotiation_info: when the fingerprint offers TLS 1.2 or lower but has no renegotiation_info extension
/// (0xff01) and no TLS_EMPTY_RENEGOTIATION_INFO_SCSV (0x00ff) cipher suite, BC appends the SCSV to the cipher suites
/// (RFC 5746), so the sent cipher list then differs from the recorded one. Browser fingerprints always carry 0xff01.</para>
/// </remarks>
public class FingerprintTlsClient : DefaultTlsClient, TlsClientHelloCustomizer, TlsClientEncryptedExtensionsProvider
{
    private readonly ClientHelloPlan _plan;
    private readonly FingerprintTlsAuthentication _authentication;

    /// <param name="fingerprint">Recorded fingerprint.</param>
    /// <param name="host">Real host name (SNI and certificate name check). IP literals send no SNI. Normalized once
    /// (IDN to ASCII, trailing dot removed, lower case) and the same string is used for SNI and name validation.</param>
    /// <param name="certificateValidationCallback">Optional final decision on the server certificate; null = accept only a
    /// certificate without any chain / name error.</param>
    public FingerprintTlsClient(TlsFingerprint fingerprint, string host, FingerprintCertificateValidationCallback? certificateValidationCallback = null)
        : base(new BcTlsCrypto(new SecureRandom()))
    {
        ArgumentNullException.ThrowIfNull(fingerprint);
        ArgumentException.ThrowIfNullOrEmpty(host);
        Host = NormalizeHost(host);
        _plan = new ClientHelloPlan(fingerprint, Host);
        _authentication = new FingerprintTlsAuthentication(Host, certificateValidationCallback);
    }

    /// <summary>Normalized host used for SNI and certificate name validation.</summary>
    public string Host { get; }

    /// <summary>IP literals (with or without brackets) are kept as is; names → IDN ASCII, no trailing dot, lower case.</summary>
    internal static string NormalizeHost(string host)
    {
        string bare = host.Trim('[', ']');
        if (System.Net.IPAddress.TryParse(bare, out _)) return host;
        string name = host.TrimEnd('.');
        if (name.Length == 0) throw new ArgumentException($"Invalid host '{host}'.", nameof(host));
        return new System.Globalization.IdnMapping().GetAscii(name).ToLowerInvariant();
    }

    /// <summary>ALPN protocol selected by the server (e.g. "h2"), or null; valid after the handshake.</summary>
    public string? NegotiatedApplicationProtocol => m_context?.SecurityParameters?.ApplicationProtocol?.GetUtf8Decoding();

    public override int[] GetCipherSuites() => (int[])_plan.CipherSuites.Clone();

    public override ProtocolVersion[] GetProtocolVersions()
        => _plan.ProtocolVersions.Select(x => ProtocolVersion.Get(x >> 8, x & 0xff)).ToArray();

    public override IDictionary<int, byte[]> GetClientExtensions()
    {
        var extensions = _plan.Extensions.ToDictionary(x => x.Key, x => (byte[])x.Value.Clone());

        // BC checks the server's key_share / ServerKeyExchange group against m_supportedGroups: always set it, from
        // supported_groups (10) when present, else from the key share groups.
        IEnumerable<int> groups = extensions.ContainsKey(ClientHelloPlan.SupportedGroupsType)
            ? TlsExtensionsUtilities.GetSupportedGroupsExtension(extensions) ?? Array.Empty<int>()
            : _plan.KeyShareGroups;
        m_supportedGroups = groups.Where(x => !TlsUtilities.IsGreaseValue(x)).ToList();
        return extensions;
    }

    public override IList<int>? GetEarlyKeyShareGroups() => _plan.KeyShareGroups.Count > 0 ? _plan.KeyShareGroups.ToList() : null;

    public override bool ShouldUseExtendedMasterSecret() => _plan.UseExtendedMasterSecret;

    public override bool ShouldUseCompatibilityMode() => _plan.SessionIdLength > 0;

    public override TlsSession? GetSessionToResume() => null;

    public override TlsAuthentication GetAuthentication() => _authentication;

    public IList<int> GetClientExtensionsOrder() => _plan.ExtensionOrder;

    public bool ShouldUseBoringSslPadding() => _plan.UsePadding;

    /// <summary>ALPS: answer with empty settings only when the server sent application_settings.</summary>
    public IDictionary<int, byte[]>? GetClientEncryptedExtensions(IDictionary<int, byte[]> serverExtensions)
    {
        if (_plan.AlpsExtensionType is int type && serverExtensions is not null && serverExtensions.ContainsKey(type))
            return new Dictionary<int, byte[]> { [type] = Array.Empty<byte>() };
        return null;
    }
}
