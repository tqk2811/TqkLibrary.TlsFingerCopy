using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace TqkLibrary.TlsFingerCopy.Http;

/// <summary>
/// Decides whether the server certificate is accepted, like <see cref="RemoteCertificateValidationCallback"/>.
/// </summary>
/// <remarks>
/// <paramref name="certificate"/> and <paramref name="chain"/> (including the certificates of its ChainElements) are
/// disposed as soon as the callback returns: they are valid only during the call. Copy what you need to keep
/// (e.g. <c>new X509Certificate2(certificate.RawData)</c>).
/// </remarks>
/// <param name="host">Host the client connected to (the normalized SNI name: IDN ASCII, lower case, no trailing dot).</param>
/// <param name="certificate">Server leaf certificate.</param>
/// <param name="chain">Chain built against the system roots, with the other certificates the server sent as extra store.</param>
/// <param name="sslPolicyErrors">Errors found by the default validation (chain and host name).</param>
/// <returns>True to accept the certificate.</returns>
public delegate bool FingerprintCertificateValidationCallback(
    string host,
    X509Certificate2 certificate,
    X509Chain chain,
    SslPolicyErrors sslPolicyErrors);
