using System.Net;
using TqkLibrary.TlsFingerCopy.Models;

namespace TqkLibrary.TlsFingerCopy.Http;

/// <summary>
/// Options of <see cref="FingerprintConnectionFactory"/> and <see cref="FingerprintHttpMessageHandler"/>.
/// </summary>
public class FingerprintHttpHandlerOptions
{
    /// <summary>Recorded fingerprint whose ClientHello is reproduced.</summary>
    public required TlsFingerprint Fingerprint { get; set; }

    /// <summary>
    /// Opens the raw transport to (host, port), e.g. through an upstream proxy (CONNECT / SOCKS). The returned stream
    /// is owned by the TLS stream. Null = direct TCP connection with NoDelay.
    /// </summary>
    public Func<string, int, CancellationToken, ValueTask<Stream>>? TransportFactory { get; set; }

    /// <summary>
    /// Final decision on the server certificate. Null = accept only a certificate whose chain builds against the
    /// system roots and whose SAN matches the host. Validation is never skipped by default.
    /// </summary>
    public FingerprintCertificateValidationCallback? CertificateValidationCallback { get; set; }

    /// <summary>Timeout of TCP connect + TLS handshake.</summary>
    public TimeSpan ConnectTimeout { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>Decompression done by the inner <see cref="SocketsHttpHandler"/> (it then adds Accept-Encoding).</summary>
    public DecompressionMethods AutomaticDecompression { get; set; } = DecompressionMethods.None;

    /// <summary>Lifetime of pooled connections; infinite by default (same as <see cref="SocketsHttpHandler"/>).</summary>
    public TimeSpan PooledConnectionLifetime { get; set; } = Timeout.InfiniteTimeSpan;

    /// <summary>
    /// Last chance to tune the inner <see cref="SocketsHttpHandler"/>s (timeouts, limits, HTTP/2 settings).
    /// The handler depends on some settings: enabling UseProxy / setting Proxy or replacing ConnectCallback makes the
    /// <see cref="FingerprintHttpMessageHandler"/> constructor throw <see cref="InvalidOperationException"/> (use
    /// <see cref="TransportFactory"/> for proxies); UseCookies and AllowAutoRedirect are forced back to false.
    /// </summary>
    public Action<SocketsHttpHandler>? ConfigureHandler { get; set; }
}
