using System.Net;
using System.Net.Sockets;
using System.Text;
using TqkLibrary.Proxy.ProxySources;
using TqkLibrary.TlsFingerCopy.Models;
using TqkLibrary.TlsFingerCopy.Recorder;
using TqkLibrary.TlsFingerCopy.Recorder.Enums;
using TqkLibrary.TlsFingerCopy.Recorder.Helpers;
using TqkLibrary.TlsFingerCopy.Recorder.Models;
using TqkLibrary.TlsFingerCopy.Tests.Core;

namespace TqkLibrary.TlsFingerCopy.Tests.Recorder;

[TestClass]
public class RecorderTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(20);

    private string _outDir = null!;

    [TestInitialize]
    public void Init()
    {
        _outDir = Path.Combine(Path.GetTempPath(), "tlsfc-recorder-" + Guid.NewGuid().ToString("N"));
    }

    [TestCleanup]
    public void Cleanup()
    {
        try { if (Directory.Exists(_outDir)) Directory.Delete(_outDir, true); } catch { }
    }

    private FingerprintRecorder CreateRecorder(RecorderProxyType proxyType = RecorderProxyType.Socks5)
        => new(new RecorderOptions
        {
            ListenEndPoint = new IPEndPoint(IPAddress.Loopback, 0),
            ProxyType = proxyType,
            OutputDirectory = _outDir,
            Source = "unit-test",
            AllowLoopbackTargets = true,
        });

    /// <summary>Opens a SOCKS5 tunnel through the recorder to the fake server; caller owns the returned objects.</summary>
    private static async Task<(IAsyncDisposable Owner, Stream Stream)> ConnectAsync(FingerprintRecorder recorder, int targetPort, CancellationToken token)
    {
        var source = new Socks5ProxySource(recorder.LocalEndPoint!);
        var connect = await source.GetConnectSourceAsync(Guid.NewGuid(), token);
        await connect.ConnectAsync(new Uri($"tcp://127.0.0.1:{targetPort}"), token);
        Stream stream = await connect.GetStreamAsync(token);
        return (new Owner(source, connect), stream);
    }

    private sealed class Owner : IAsyncDisposable
    {
        private readonly TqkLibrary.Proxy.Interfaces.IProxySource _source;
        private readonly IDisposable _connect;

        public Owner(TqkLibrary.Proxy.Interfaces.IProxySource source, IDisposable connect)
        {
            _source = source;
            _connect = connect;
        }

        public async ValueTask DisposeAsync()
        {
            _connect.Dispose();
            await _source.DisposeAsync();
        }
    }

    private static async Task ReadExactAsync(Stream stream, byte[] buffer, CancellationToken token)
    {
        int read = 0;
        while (read < buffer.Length)
        {
            int n = await stream.ReadAsync(buffer.AsMemory(read), token);
            if (n == 0) throw new EndOfStreamException();
            read += n;
        }
    }

    [TestMethod]
    public async Task ClientHello_IsCaptured_AndTrafficPassesThrough()
    {
        using var cts = new CancellationTokenSource(Timeout);
        byte[] hello = ClientHelloBuilder.Chrome("example.test").BuildRecords(maxFragment: 120);
        byte[] reply = { 1, 2, 3, 4, 5, 6, 7 };

        await using var server = new FakeEchoServer(hello.Length, reply);
        await using var recorder = CreateRecorder();
        var captured = new TaskCompletionSource<ClientHelloCapturedEventArgs>(TaskCreationOptions.RunContinuationsAsynchronously);
        recorder.ClientHelloCaptured += (_, e) => captured.TrySetResult(e);
        recorder.Start();

        var (owner, stream) = await ConnectAsync(recorder, server.Port, cts.Token);
        await using (owner)
        {
            // split into uneven writes, including a cut inside the 5-byte record header
            int[] cuts = { 3, 40, 130, 131, hello.Length };
            int pos = 0;
            foreach (int cut in cuts)
            {
                await stream.WriteAsync(hello.AsMemory(pos, cut - pos), cts.Token);
                await stream.FlushAsync(cts.Token);
                pos = cut;
                await Task.Delay(20, cts.Token);
            }

            ClientHelloCapturedEventArgs args = await captured.Task.WaitAsync(cts.Token);
            Assert.AreEqual("example.test", args.ServerName);
            Assert.AreEqual("example.test", args.Key);
            Assert.AreEqual("127.0.0.1", args.TargetHost);
            Assert.AreEqual(server.Port, args.TargetPort);
            Assert.IsNotEmpty(args.ClientHello.CipherSuites);

            byte[] atServer = await server.Received.WaitAsync(cts.Token);
            CollectionAssert.AreEqual(hello, atServer);

            byte[] back = new byte[reply.Length];
            await ReadExactAsync(stream, back, cts.Token);
            CollectionAssert.AreEqual(reply, back);
        }

        Assert.AreEqual(1, recorder.Session.SampleCount);

        IReadOnlyList<string> files = await recorder.SaveAllAsync(cts.Token);
        Assert.HasCount(1, files);
        Assert.AreEqual(recorder.RunDirectory, Path.GetDirectoryName(files[0]));
        Assert.AreEqual(_outDir, Path.GetDirectoryName(recorder.RunDirectory));
        Assert.AreEqual("example.test.json", Path.GetFileName(files[0]));
        TlsFingerprint loaded = await new TlsFingerprintFile().LoadAsync(files[0], cts.Token);
        Assert.AreEqual("example.test", loaded.ServerName);
        Assert.AreEqual("unit-test", loaded.Source);
    }

    [TestMethod]
    public async Task NonTlsTraffic_PassesUntouched_AndIsNotCaptured()
    {
        using var cts = new CancellationTokenSource(Timeout);
        byte[] request = System.Text.Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\nHost: x\r\n\r\n");
        byte[] reply = System.Text.Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\n\r\n");

        await using var server = new FakeEchoServer(request.Length, reply);
        await using var recorder = CreateRecorder();
        int events = 0;
        recorder.ClientHelloCaptured += (_, _) => Interlocked.Increment(ref events);
        recorder.Start();

        var (owner, stream) = await ConnectAsync(recorder, server.Port, cts.Token);
        await using (owner)
        {
            await stream.WriteAsync(request, cts.Token);
            await stream.FlushAsync(cts.Token);

            CollectionAssert.AreEqual(request, await server.Received.WaitAsync(cts.Token));
            byte[] back = new byte[reply.Length];
            await ReadExactAsync(stream, back, cts.Token);
            CollectionAssert.AreEqual(reply, back);
        }

        Assert.AreEqual(0, events);
        Assert.AreEqual(0, recorder.Session.SampleCount);
        IReadOnlyList<string> files = await recorder.StopAsync(cts.Token);
        Assert.IsEmpty(files);
    }

    [TestMethod]
    public async Task StopAsync_SavesCaptures()
    {
        using var cts = new CancellationTokenSource(Timeout);
        byte[] hello = ClientHelloBuilder.Chrome("save.test").BuildRecords();

        await using var server = new FakeEchoServer(hello.Length, new byte[] { 9 });
        await using var recorder = CreateRecorder();
        var captured = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        recorder.ClientHelloCaptured += (_, _) => captured.TrySetResult(true);
        recorder.Start();

        var (owner, stream) = await ConnectAsync(recorder, server.Port, cts.Token);
        await using (owner)
        {
            await stream.WriteAsync(hello, cts.Token);
            await stream.FlushAsync(cts.Token);
            await captured.Task.WaitAsync(cts.Token);
        }

        IReadOnlyList<string> files = await recorder.StopAsync(cts.Token);
        Assert.HasCount(1, files);
        Assert.IsTrue(File.Exists(files[0]));
        Assert.AreEqual(recorder.RunDirectory, Path.GetDirectoryName(files[0]), "StopAsync reuses the run folder");
        Assert.IsEmpty(await recorder.StopAsync(cts.Token), "second stop is a no-op");
    }

    [TestMethod]
    public async Task Session_GroupsByServerNameOrHost_AndSplitsIncompatibleSamples()
    {
        var parser = new ClientHelloParser();
        ClientHelloInfo withSni = parser.Parse(ClientHelloBuilder.Chrome("a.test").BuildRecords());
        ClientHelloInfo sameSni = parser.Parse(ClientHelloBuilder.Chrome("a.test").BuildRecords());

        var other = ClientHelloBuilder.Chrome("a.test");
        other.AddExtension(0x4469, new byte[] { 0, 1 }); // extra extension => different set
        ClientHelloInfo differentSet = parser.Parse(other.BuildRecords());

        var noSni = ClientHelloBuilder.Chrome("x");
        noSni.Extensions.RemoveAll(e => e.Type == 0);
        ClientHelloInfo withoutSni = parser.Parse(noSni.BuildRecords());
        Assert.IsNull(withoutSni.ServerName);

        var session = new CaptureSession();
        Assert.AreEqual("a.test", session.Add(withSni, "10.0.0.1"));
        session.Add(sameSni, "10.0.0.1");
        session.Add(differentSet, "10.0.0.2");
        Assert.AreEqual("93.184.216.34", session.Add(withoutSni, "93.184.216.34"));

        IReadOnlyList<string> files = await session.SaveAsync(_outDir, "src");
        string[] names = files.Select(Path.GetFileName).Order().ToArray()!;
        CollectionAssert.AreEqual(new[] { "93.184.216.34.json", "a.test-1.json", "a.test-2.json" }, names);
        var merger = new FingerprintMerger();
        Assert.IsTrue(merger.AreCompatible(withSni, sameSni));
        Assert.IsFalse(merger.AreCompatible(withSni, differentSet));
    }

    [TestMethod]
    public void FileNameHelper_Sanitizes()
    {
        Assert.AreEqual("a.b-c_d", FileNameHelper.Sanitize("A.b-c_d"));
        Assert.AreEqual("___1_", FileNameHelper.Sanitize("[::1]"));
        Assert.AreEqual("unknown", FileNameHelper.Sanitize(""));
        Assert.AreEqual("unknown", FileNameHelper.Sanitize(".."));
        Assert.DoesNotContain(':', FileNameHelper.Sanitize("host:443"));
        Assert.DoesNotContain('/', FileNameHelper.Sanitize("a/b\\c"));
    }
    [TestMethod]
    [DataRow("con", "_con")]
    [DataRow("CON", "_con")]
    [DataRow("nul", "_nul")]
    [DataRow("com1", "_com1")]
    [DataRow("LPT9", "_lpt9")]
    [DataRow("con.example", "_con.example")]
    [DataRow("aux.test", "_aux.test")]
    [DataRow("console.test", "console.test")]
    [DataRow("com10", "com10")]
    [DataRow("example.con", "example.con")]
    public void FileNameHelper_AvoidsReservedDeviceNames(string key, string expected)
    {
        Assert.AreEqual(expected, FileNameHelper.Sanitize(key));
    }

    [TestMethod]
    public async Task HalfClose_IsForwardedToServer_AndReplyStillArrives()
    {
        using var cts = new CancellationTokenSource(Timeout);
        byte[] hello = ClientHelloBuilder.Chrome("half.test").BuildRecords();
        byte[] reply = { 10, 20, 30, 40 };

        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        try
        {
            int port = ((IPEndPoint)listener.LocalEndpoint).Port;
            var serverSawEof = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
            Task serverTask = Task.Run(async () =>
            {
                try
                {
                    using TcpClient c = await listener.AcceptTcpClientAsync(cts.Token);
                    using NetworkStream s = c.GetStream();
                    var data = new MemoryStream();
                    var buf = new byte[4096];
                    int n;
                    while ((n = await s.ReadAsync(buf, cts.Token)) > 0) data.Write(buf, 0, n);
                    serverSawEof.TrySetResult(data.ToArray()); // read returned 0 => FIN received
                    await s.WriteAsync(reply, cts.Token);
                }
                catch (Exception ex) { serverSawEof.TrySetException(ex); }
            }, cts.Token);

            await using var recorder = CreateRecorder();
            var captured = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            recorder.ClientHelloCaptured += (_, _) => captured.TrySetResult(true);
            recorder.Start();

            var (owner, stream) = await ConnectAsync(recorder, port, cts.Token);
            await using (owner)
            {
                var network = stream as NetworkStream;
                Assert.IsNotNull(network, "client side of the tunnel is expected to be a NetworkStream");
                await stream.WriteAsync(hello, cts.Token);
                await stream.FlushAsync(cts.Token);
                network.Socket.Shutdown(SocketShutdown.Send);

                byte[] atServer = await serverSawEof.Task.WaitAsync(cts.Token);
                CollectionAssert.AreEqual(hello, atServer);

                byte[] back = new byte[reply.Length];
                await ReadExactAsync(stream, back, cts.Token);
                CollectionAssert.AreEqual(reply, back);
                await captured.Task.WaitAsync(cts.Token);
            }
            await serverTask;
        }
        finally
        {
            listener.Stop();
        }
    }

    [TestMethod]
    public async Task HttpConnect_ClientHello_IsCaptured_AndTrafficPassesThrough()
    {
        using var cts = new CancellationTokenSource(Timeout);
        byte[] hello = ClientHelloBuilder.Chrome("http.test").BuildRecords();
        byte[] reply = { 5, 4, 3, 2, 1 };

        await using var server = new FakeEchoServer(hello.Length, reply);
        await using var recorder = CreateRecorder(RecorderProxyType.Http);
        var captured = new TaskCompletionSource<ClientHelloCapturedEventArgs>(TaskCreationOptions.RunContinuationsAsynchronously);
        recorder.ClientHelloCaptured += (_, e) => captured.TrySetResult(e);
        recorder.Start();

        using var client = new TcpClient();
        await client.ConnectAsync(recorder.LocalEndPoint!, cts.Token);
        using NetworkStream stream = client.GetStream();

        string request = $"CONNECT 127.0.0.1:{server.Port} HTTP/1.1\r\nHost: 127.0.0.1:{server.Port}\r\n\r\n";
        await stream.WriteAsync(System.Text.Encoding.ASCII.GetBytes(request), cts.Token);

        // read the response head byte by byte so no tunnel data is consumed
        var head = new StringBuilder();
        var one = new byte[1];
        while (!head.ToString().EndsWith("\r\n\r\n", StringComparison.Ordinal))
        {
            Assert.AreEqual(1, await stream.ReadAsync(one, cts.Token), "proxy closed before the CONNECT response ended");
            head.Append((char)one[0]);
        }
        StringAssert.StartsWith(head.ToString(), "HTTP/1.1 200");

        await stream.WriteAsync(hello, cts.Token);
        await stream.FlushAsync(cts.Token);

        ClientHelloCapturedEventArgs args = await captured.Task.WaitAsync(cts.Token);
        Assert.AreEqual("http.test", args.ServerName);
        CollectionAssert.AreEqual(hello, await server.Received.WaitAsync(cts.Token));

        byte[] back = new byte[reply.Length];
        await ReadExactAsync(stream, back, cts.Token);
        CollectionAssert.AreEqual(reply, back);
        Assert.AreEqual(1, recorder.Session.SampleCount);
    }
}
