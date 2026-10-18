using TqkLibrary.Proxy.Interfaces;
using TqkLibrary.TlsFingerCopy.Models;

namespace TqkLibrary.TlsFingerCopy.Recorder.Interception;

/// <summary>
/// <see cref="IProxySource"/> decorator whose connect tunnels tee the client-to-server bytes.
/// Ownership: the wrapped source is borrowed and NOT disposed here; the recorder owns it.
/// </summary>
internal sealed class CapturingProxySource : IProxySource
{
    private readonly IProxySource _inner;
    private readonly Action<Uri, ClientHelloInfo> _onCaptured;

    public CapturingProxySource(IProxySource inner, Action<Uri, ClientHelloInfo> onCaptured)
    {
        _inner = inner ?? throw new ArgumentNullException(nameof(inner));
        _onCaptured = onCaptured ?? throw new ArgumentNullException(nameof(onCaptured));
    }

    public async Task<IConnectSource> GetConnectSourceAsync(Guid tunnelId, CancellationToken cancellationToken = default)
    {
        IConnectSource connectSource = await _inner.GetConnectSourceAsync(tunnelId, cancellationToken).ConfigureAwait(false);
        return new CapturingConnectSource(connectSource, _onCaptured);
    }

    public ValueTask DisposeAsync() => default;
}
