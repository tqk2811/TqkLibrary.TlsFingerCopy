using System.Net;
using System.Net.Sockets;
using TqkLibrary.TlsFingerCopy.Models;

namespace TqkLibrary.TlsFingerCopy.Tests.Http;

/// <summary>
/// Loopback TCP server that reads the first ClientHello of one connection and closes it.
/// </summary>
internal sealed class ClientHelloCaptureServer : IDisposable
{
    private readonly TcpListener _listener = new(IPAddress.Loopback, 0);

    public ClientHelloCaptureServer()
    {
        _listener.Start();
    }

    public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;

    /// <summary>Accepts one connection and returns the parsed ClientHello (raw record bytes kept for record version).</summary>
    public async Task<ClientHelloInfo> CaptureAsync(CancellationToken cancellationToken)
    {
        using TcpClient client = await _listener.AcceptTcpClientAsync(cancellationToken);
        using NetworkStream stream = client.GetStream();
        var reassembler = new TlsRecordReassembler();
        var raw = new List<byte>();
        byte[] buffer = new byte[4096];
        while (true)
        {
            int read = await stream.ReadAsync(buffer, cancellationToken);
            if (read == 0) throw new IOException("Client closed before a full ClientHello.");
            raw.AddRange(buffer.AsSpan(0, read).ToArray());
            if (reassembler.TryFeed(buffer.AsSpan(0, read), out _)) break;
            if (reassembler.IsFailed) throw new IOException("Not a ClientHello.");
        }
        return new ClientHelloParser().Parse(raw.ToArray());
    }

    public void Dispose() => _listener.Stop();
}
