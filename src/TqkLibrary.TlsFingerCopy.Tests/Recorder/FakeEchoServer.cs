using System.Net;
using System.Net.Sockets;

namespace TqkLibrary.TlsFingerCopy.Tests.Recorder;

/// <summary>
/// Loopback TCP server: records every byte it receives and answers each received chunk batch with a fixed reply
/// once <c>expectedBytes</c> have arrived. Owns its listener; dispose to stop.
/// </summary>
internal sealed class FakeEchoServer : IAsyncDisposable
{
    private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
    private readonly byte[] _reply;
    private readonly int _expectedBytes;
    private readonly TaskCompletionSource<byte[]> _received = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _loop;

    public FakeEchoServer(int expectedBytes, byte[] reply)
    {
        _expectedBytes = expectedBytes;
        _reply = reply;
        _listener.Start();
        _loop = Task.Run(RunAsync);
    }

    public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;

    /// <summary>Completes with the first <c>expectedBytes</c> bytes received from the client.</summary>
    public Task<byte[]> Received => _received.Task;

    private async Task RunAsync()
    {
        try
        {
            using TcpClient client = await _listener.AcceptTcpClientAsync(_cts.Token);
            using NetworkStream stream = client.GetStream();
            var data = new MemoryStream();
            var buffer = new byte[4096];
            while (data.Length < _expectedBytes)
            {
                int n = await stream.ReadAsync(buffer, _cts.Token);
                if (n == 0) break;
                data.Write(buffer, 0, n);
            }
            _received.TrySetResult(data.ToArray());
            await stream.WriteAsync(_reply, _cts.Token);
            // keep the connection open until the client closes it or the server is disposed
            while (await stream.ReadAsync(buffer, _cts.Token) > 0) { }
        }
        catch (Exception ex)
        {
            _received.TrySetException(ex);
        }
    }

    public async ValueTask DisposeAsync()
    {
        _cts.Cancel();
        _listener.Stop();
        try { await _loop; } catch { }
        _cts.Dispose();
    }
}
