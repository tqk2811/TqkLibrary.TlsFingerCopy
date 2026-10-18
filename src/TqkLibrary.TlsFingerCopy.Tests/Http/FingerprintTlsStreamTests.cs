using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using TqkLibrary.TlsFingerCopy.Http;

namespace TqkLibrary.TlsFingerCopy.Tests.Http;

/// <summary>
/// <see cref="FingerprintTlsStream"/> against an SslStream server over loopback, with a transport whose writes can stall.
/// </summary>
[TestClass]
public sealed class FingerprintTlsStreamTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

    [TestMethod]
    public async Task Read_CompletesWhileWriterIsStalledOnTransport()
    {
        await using var pair = await TlsPair.CreateAsync();
        pair.Transport.HoldWrites();
        Task write = pair.Client.WriteAsync(new byte[4096]).AsTask();
        await pair.Transport.WriteHeld.WaitAsync(Timeout);

        await pair.ServerSsl.WriteAsync("ping"u8.ToArray());
        await pair.ServerSsl.FlushAsync();
        byte[] buffer = new byte[16];
        int read = await pair.Client.ReadAsync(buffer).AsTask().WaitAsync(Timeout);
        Assert.AreEqual("ping", Encoding.ASCII.GetString(buffer, 0, read));

        pair.Transport.ReleaseWrites();
        await write.WaitAsync(Timeout);
        byte[] received = new byte[4096];
        await pair.ServerSsl.ReadExactlyAsync(received).AsTask().WaitAsync(Timeout);
    }

    [TestMethod]
    public async Task Write_CanceledMidRecord_FaultsStreamInsteadOfCorruptingFraming()
    {
        await using var pair = await TlsPair.CreateAsync();
        pair.Transport.HoldWrites();
        using var cts = new CancellationTokenSource();
        Task write = pair.Client.WriteAsync(new byte[4096], cts.Token).AsTask();
        await pair.Transport.WriteHeld.WaitAsync(Timeout);

        cts.Cancel();
        await Assert.ThrowsAsync<OperationCanceledException>(() => write.WaitAsync(Timeout));

        // Half a record is on the wire: the stream must refuse to send anything after it.
        pair.Transport.ReleaseWrites();
        await Assert.ThrowsAsync<IOException>(() => pair.Client.WriteAsync(new byte[16]).AsTask().WaitAsync(Timeout));
    }

    [TestMethod]
    public async Task ServerAlert_SurfacesAsIOException()
    {
        await using var pair = await TlsPair.CreateAsync();
        // Garbage instead of a TLS record: BC raises a fatal alert, the stream must report a plain IOException.
        await pair.ServerTcp.GetStream().WriteAsync(new byte[] { 0x17, 0x03, 0x03, 0x00, 0x20, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 });
        var ex = await Assert.ThrowsAsync<IOException>(() => pair.Client.ReadAsync(new byte[16]).AsTask().WaitAsync(Timeout));
        Assert.AreEqual(typeof(IOException), ex.GetType());
        Assert.IsInstanceOfType<Org.BouncyCastle.Tls.TlsException>(ex.InnerException);
    }

    [TestMethod]
    public async Task ZeroByteRead_WaitsForPlaintextInsteadOfReturningImmediately()
    {
        await using var pair = await TlsPair.CreateAsync();
        Task<int> zeroRead = pair.Client.ReadAsync(Memory<byte>.Empty).AsTask();
        await Task.Delay(300);
        Assert.IsFalse(zeroRead.IsCompleted, "A zero-byte read must wait for data, SocketsHttpHandler uses it as a readiness probe.");

        await pair.ServerSsl.WriteAsync("ping"u8.ToArray());
        await pair.ServerSsl.FlushAsync();
        Assert.AreEqual(0, await zeroRead.WaitAsync(Timeout));

        byte[] buffer = new byte[16];
        int read = await pair.Client.ReadAsync(buffer).AsTask().WaitAsync(Timeout);
        Assert.AreEqual("ping", Encoding.ASCII.GetString(buffer, 0, read));
    }

    [TestMethod]
    public async Task TransportDisposedDuringRead_SurfacesAsIOException()
    {
        await using var pair = await TlsPair.CreateAsync();
        Task<int> read = pair.Client.ReadAsync(new byte[16]).AsTask();
        await Task.Delay(100);
        pair.Transport.Dispose();
        var ex = await Assert.ThrowsAsync<IOException>(() => read.WaitAsync(Timeout));
        Assert.AreEqual(typeof(IOException), ex.GetType());
    }

    private sealed class TlsPair : IAsyncDisposable
    {
        private readonly TcpListener _listener;
        private readonly X509Certificate2 _certificate;

        private TlsPair(TcpListener listener, X509Certificate2 certificate, TcpClient serverTcp, SslStream serverSsl, GatedStream transport, FingerprintTlsStream client)
        {
            _listener = listener;
            _certificate = certificate;
            ServerTcp = serverTcp;
            ServerSsl = serverSsl;
            Transport = transport;
            Client = client;
        }

        public TcpClient ServerTcp { get; }
        public SslStream ServerSsl { get; }
        public GatedStream Transport { get; }
        public FingerprintTlsStream Client { get; }

        public static async Task<TlsPair> CreateAsync()
        {
            var certificate = TestCertificates.CreateLocalhost();
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            int port = ((IPEndPoint)listener.LocalEndpoint).Port;

            Task<TcpClient> accept = listener.AcceptTcpClientAsync();
            var tcp = new TcpClient { NoDelay = true };
            await tcp.ConnectAsync(IPAddress.Loopback, port);
            TcpClient serverTcp = await accept;
            var serverSsl = new SslStream(serverTcp.GetStream());
            Task serverAuth = serverSsl.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
            {
                ServerCertificate = certificate,
                ApplicationProtocols = new List<SslApplicationProtocol> { SslApplicationProtocol.Http11 },
            });

            var transport = new GatedStream(tcp.GetStream());
            var tlsClient = new FingerprintTlsClient(TestFingerprints.Chrome(randomized: false), "localhost", (_, _, _, _) => true);
            FingerprintTlsStream client = await FingerprintTlsStream.ConnectAsync(transport, tlsClient).WaitAsync(Timeout);
            await serverAuth.WaitAsync(Timeout);
            return new TlsPair(listener, certificate, serverTcp, serverSsl, transport, client);
        }

        public async ValueTask DisposeAsync()
        {
            Transport.ReleaseWrites();
            await Client.DisposeAsync();
            await ServerSsl.DisposeAsync();
            ServerTcp.Dispose();
            _listener.Stop();
            _certificate.Dispose();
        }
    }
}
