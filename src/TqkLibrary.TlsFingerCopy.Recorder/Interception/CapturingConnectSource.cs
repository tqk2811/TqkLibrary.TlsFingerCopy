using System.Net.Sockets;
using TqkLibrary.Proxy.Interfaces;
using TqkLibrary.TlsFingerCopy.Models;

namespace TqkLibrary.TlsFingerCopy.Recorder.Interception;

/// <summary>
/// Wraps an <see cref="IConnectSource"/> and returns its stream wrapped in a <see cref="CapturingNetworkStream"/> (NetworkStream) or <see cref="CapturingStream"/> (other streams).
/// Ownership: disposes the wrapped connect source.
/// </summary>
internal sealed class CapturingConnectSource : IConnectSource
{
    private readonly IConnectSource _inner;
    private readonly Action<Uri, ClientHelloInfo> _onCaptured;
    private Uri? _target;

    public CapturingConnectSource(IConnectSource inner, Action<Uri, ClientHelloInfo> onCaptured)
    {
        _inner = inner ?? throw new ArgumentNullException(nameof(inner));
        _onCaptured = onCaptured ?? throw new ArgumentNullException(nameof(onCaptured));
    }

    public async Task ConnectAsync(Uri address, CancellationToken cancellationToken = default)
    {
        _target = address;
        await _inner.ConnectAsync(address, cancellationToken).ConfigureAwait(false);
    }

    public async Task<Stream> GetStreamAsync(CancellationToken cancellationToken = default)
    {
        Stream stream = await _inner.GetStreamAsync(cancellationToken).ConfigureAwait(false);
        Uri target = _target ?? throw new InvalidOperationException("ConnectAsync must be called first.");
        Action<ClientHelloInfo> onCaptured = info => _onCaptured(target, info);
        // A NetworkStream must stay a NetworkStream so the proxy library can half-close the socket.
        return stream is NetworkStream networkStream
            ? new CapturingNetworkStream(networkStream, onCaptured)
            : new CapturingStream(stream, onCaptured);
    }

    public void Dispose() => _inner.Dispose();
}
