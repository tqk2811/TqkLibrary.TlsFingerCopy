using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace TqkLibrary.TlsFingerCopy.Tests.Http;

internal static class TestCertificates
{
    /// <summary>Self-signed ECDSA P-256 server certificate for "localhost" (SAN + serverAuth EKU).</summary>
    public static X509Certificate2 CreateLocalhost()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=localhost", key, HashAlgorithmName.SHA256);
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName("localhost");
        request.CertificateExtensions.Add(san.Build());
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, false));
        using var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        return new X509Certificate2(cert.Export(X509ContentType.Pfx));
    }
}
