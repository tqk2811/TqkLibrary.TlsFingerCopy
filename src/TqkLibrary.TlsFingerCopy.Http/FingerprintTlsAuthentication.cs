using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Tls;

namespace TqkLibrary.TlsFingerCopy.Http;

/// <summary>
/// Validates the server certificate with .NET <see cref="X509Chain"/> (system roots) and a host name check,
/// optionally deferring the final decision to a <see cref="FingerprintCertificateValidationCallback"/>.
/// BC itself verifies the handshake signature (CertificateVerify / ServerKeyExchange) with the leaf key.
/// </summary>
internal class FingerprintTlsAuthentication : TlsAuthentication
{
    private readonly string _host;
    private readonly FingerprintCertificateValidationCallback? _callback;

    public FingerprintTlsAuthentication(string host, FingerprintCertificateValidationCallback? callback)
    {
        _host = host;
        _callback = callback;
    }

    public void NotifyServerCertificate(TlsServerCertificate serverCertificate)
    {
        var bcChain = serverCertificate.Certificate;
        if (bcChain is null || bcChain.IsEmpty)
            throw new TlsFatalAlert(AlertDescription.bad_certificate);

        var certificates = new List<X509Certificate2>(bcChain.Length);
        try
        {
            for (int i = 0; i < bcChain.Length; i++)
                certificates.Add(new X509Certificate2(bcChain.GetCertificateAt(i).GetEncoded()));

            X509Certificate2 leaf = certificates[0];
            using var chain = new X509Chain();
            try
            {
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                chain.ChainPolicy.ApplicationPolicy.Add(new System.Security.Cryptography.Oid("1.3.6.1.5.5.7.3.1")); // serverAuth
                for (int i = 1; i < certificates.Count; i++) chain.ChainPolicy.ExtraStore.Add(certificates[i]);

                var errors = SslPolicyErrors.None;
                if (!chain.Build(leaf)) errors |= SslPolicyErrors.RemoteCertificateChainErrors;
                if (!MatchesHost(leaf)) errors |= SslPolicyErrors.RemoteCertificateNameMismatch;

                bool accepted = _callback is null ? errors == SslPolicyErrors.None : _callback(_host, leaf, chain, errors);
                if (!accepted)
                    throw new TlsFatalAlert(AlertDescription.bad_certificate, $"Server certificate rejected: {errors}");
            }
            finally
            {
                // ChainElements hands out new X509Certificate2 copies: release them with the chain.
                foreach (var element in chain.ChainElements) element.Certificate.Dispose();
            }
        }
        finally
        {
            foreach (var certificate in certificates) certificate.Dispose();
        }
    }

    public TlsCredentials? GetClientCredentials(Org.BouncyCastle.Tls.CertificateRequest certificateRequest) => null;

    private bool MatchesHost(X509Certificate2 leaf)
    {
        string host = _host.Trim('[', ']');
        bool isIp = IPAddress.TryParse(host, out _);
        return leaf.MatchesHostname(host, allowWildcards: !isIp, allowCommonName: false);
    }
}
