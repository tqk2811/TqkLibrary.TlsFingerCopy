using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using TqkLibrary.TlsFingerCopy.Http;
using TqkLibrary.TlsFingerCopy.Models;

namespace TqkLibrary.TlsFingerCopy.Tests.Http;

/// <summary>
/// End to end over loopback: HTTP/1.1 through <see cref="FingerprintHttpMessageHandler"/> against an SslStream server.
/// </summary>
[TestClass]
public sealed class FingerprintHttpMessageHandlerTests
{
    [TestMethod]
    public async Task Get_Http11Server_RetriesAfterAlpnMismatchAndReturnsBody()
    {
        using var cert = TestCertificates.CreateLocalhost();
        await using var server = new LoopbackHttpsServer(cert);
        int callbackCalls = 0;
        using var handler = new FingerprintHttpMessageHandler(new FingerprintHttpHandlerOptions
        {
            Fingerprint = TestFingerprints.Chrome(randomized: true),
            TransportFactory = server.ConnectAsync,
            CertificateValidationCallback = (host, certificate, _, errors) =>
            {
                Interlocked.Increment(ref callbackCalls);
                // Self-signed: only the chain is wrong, the SAN matches.
                return host == "localhost"
                    && errors == SslPolicyErrors.RemoteCertificateChainErrors
                    && certificate.Thumbprint == cert.Thumbprint;
            },
        });
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(20) };

        var uri = new Uri($"https://localhost:{server.Port}/path?q=1");
        using var response = await client.GetAsync(uri);
        string body = await response.Content.ReadAsStringAsync();

        Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
        Assert.AreEqual("hello", body);
        Assert.AreEqual(uri, response.RequestMessage!.RequestUri);
        Assert.AreEqual(new Version(1, 1), response.Version);
        StringAssert.StartsWith(server.LastRequestHead, "GET /path?q=1 HTTP/1.1\r\n");
        StringAssert.Contains(server.LastRequestHead, $"Host: localhost:{server.Port}\r\n");
        // First connection guessed h2 (fingerprint offers it), server chose http/1.1 → one retry
        Assert.AreEqual(2, server.ConnectionCount);
        Assert.AreEqual(2, callbackCalls);

        // Second request: ALPN known, no extra handshake needed for the protocol guess
        using var second = await client.GetAsync(uri);
        Assert.AreEqual("hello", await second.Content.ReadAsStringAsync());
        Assert.AreEqual(3, server.ConnectionCount); // server closes after each response
    }

    [TestMethod]
    public async Task Get_SelfSignedWithoutCallback_IsRejected()
    {
        using var cert = TestCertificates.CreateLocalhost();
        await using var server = new LoopbackHttpsServer(cert);
        using var handler = new FingerprintHttpMessageHandler(new FingerprintHttpHandlerOptions
        {
            Fingerprint = TestFingerprints.Chrome(randomized: false),
            TransportFactory = server.ConnectAsync,
        });
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(20) };

        await Assert.ThrowsAsync<HttpRequestException>(() => client.GetAsync($"https://localhost:{server.Port}/"));
    }

    [TestMethod]
    public async Task Get_ConcurrentFirstRequestsToHttp11Server_AllSucceedAfterAlpnRetries()
    {
        using var cert = TestCertificates.CreateLocalhost();
        await using var server = new LoopbackHttpsServer(cert);
        using var handler = new FingerprintHttpMessageHandler(new FingerprintHttpHandlerOptions
        {
            Fingerprint = TestFingerprints.Chrome(randomized: true), // offers h2, server only http/1.1
            TransportFactory = server.ConnectAsync,
            CertificateValidationCallback = (_, _, _, _) => true,
        });
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(30) };

        var uri = new Uri($"https://localhost:{server.Port}/");
        var responses = await Task.WhenAll(Enumerable.Range(0, 5).Select(async _ =>
        {
            using var response = await client.GetAsync(uri);
            return (response.Version, Body: await response.Content.ReadAsStringAsync());
        }));
        foreach (var (version, body) in responses)
        {
            Assert.AreEqual("hello", body);
            Assert.AreEqual(new Version(1, 1), version);
        }
    }

    [TestMethod]
    public void Constructor_ConfigureHandlerEnablesProxy_Throws()
    {
        Assert.ThrowsExactly<InvalidOperationException>(() => new FingerprintHttpMessageHandler(new FingerprintHttpHandlerOptions
        {
            Fingerprint = TestFingerprints.Chrome(randomized: false),
            ConfigureHandler = h => h.Proxy = new WebProxy("http://127.0.0.1:8888"),
        }));
        Assert.ThrowsExactly<InvalidOperationException>(() => new FingerprintHttpMessageHandler(new FingerprintHttpHandlerOptions
        {
            Fingerprint = TestFingerprints.Chrome(randomized: false),
            ConfigureHandler = h => h.UseProxy = true,
        }));
    }

    [TestMethod]
    public void Constructor_ConfigureHandlerReplacesConnectCallback_Throws()
    {
        Assert.ThrowsExactly<InvalidOperationException>(() => new FingerprintHttpMessageHandler(new FingerprintHttpHandlerOptions
        {
            Fingerprint = TestFingerprints.Chrome(randomized: false),
            ConfigureHandler = h => h.ConnectCallback = (_, _) => ValueTask.FromResult<Stream>(new MemoryStream()),
        }));
    }

    [TestMethod]
    public async Task ConfigureHandlerEnablingCookiesAndRedirects_IsForcedBack()
    {
        using var cert = TestCertificates.CreateLocalhost();
        await using var server = new LoopbackHttpsServer(cert, "HTTP/1.1 302 Found\r\nLocation: /other\r\nSet-Cookie: a=b\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        using var handler = new FingerprintHttpMessageHandler(new FingerprintHttpHandlerOptions
        {
            Fingerprint = TestFingerprints.Chrome(randomized: false),
            TransportFactory = server.ConnectAsync,
            CertificateValidationCallback = (_, _, _, _) => true,
            ConfigureHandler = h =>
            {
                h.UseCookies = true;
                h.AllowAutoRedirect = true;
            },
        });
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(20) };

        using var response = await client.GetAsync($"https://localhost:{server.Port}/");
        Assert.AreEqual(HttpStatusCode.Found, response.StatusCode);
        // h2 guess + ALPN retry = 2 connections; a followed redirect would open more (server closes after each response)
        Assert.AreEqual(2, server.ConnectionCount);
    }

    /// <summary>TLS server (Schannel/OpenSSL via SslStream) answering every request with "hello" and closing.</summary>
    private sealed class LoopbackHttpsServer : IAsyncDisposable
    {
        private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
        private readonly X509Certificate2 _certificate;
        private readonly CancellationTokenSource _cts = new();
        private readonly Task _acceptLoop;
        private int _connectionCount;

        private readonly string _response;

        public LoopbackHttpsServer(X509Certificate2 certificate, string response = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello")
        {
            _certificate = certificate;
            _response = response;
            _listener.Start();
            _acceptLoop = AcceptLoopAsync();
        }

        public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;

        public int ConnectionCount => Volatile.Read(ref _connectionCount);

        public string LastRequestHead { get; private set; } = string.Empty;

        public async ValueTask<Stream> ConnectAsync(string host, int port, CancellationToken cancellationToken)
        {
            Assert.AreEqual("localhost", host);
            Assert.AreEqual(Port, port);
            var tcp = new TcpClient { NoDelay = true };
            await tcp.ConnectAsync(IPAddress.Loopback, Port, cancellationToken);
            return tcp.GetStream();
        }

        private async Task AcceptLoopAsync()
        {
            while (!_cts.IsCancellationRequested)
            {
                TcpClient client;
                try
                {
                    client = await _listener.AcceptTcpClientAsync(_cts.Token);
                }
                catch
                {
                    return;
                }
                Interlocked.Increment(ref _connectionCount);
                _ = HandleAsync(client);
            }
        }

        private async Task HandleAsync(TcpClient client)
        {
            using (client)
            {
                try
                {
                    await using var ssl = new SslStream(client.GetStream());
                    await ssl.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
                    {
                        ServerCertificate = _certificate,
                        ApplicationProtocols = new List<SslApplicationProtocol> { SslApplicationProtocol.Http11 },
                    }, _cts.Token);

                    var head = new StringBuilder();
                    byte[] buffer = new byte[4096];
                    while (!head.ToString().Contains("\r\n\r\n"))
                    {
                        int read = await ssl.ReadAsync(buffer, _cts.Token);
                        if (read == 0) return;
                        head.Append(Encoding.ASCII.GetString(buffer, 0, read));
                    }
                    LastRequestHead = head.ToString();
                    byte[] response = Encoding.ASCII.GetBytes(_response);
                    await ssl.WriteAsync(response, _cts.Token);
                    await ssl.FlushAsync(_cts.Token);
                    await ssl.ShutdownAsync();
                }
                catch
                {
                    // client side failures (e.g. rejected certificate, ALPN mismatch) end here
                }
            }
        }

        public async ValueTask DisposeAsync()
        {
            _cts.Cancel();
            _listener.Stop();
            try { await _acceptLoop; } catch { }
            _cts.Dispose();
        }
    }
}
