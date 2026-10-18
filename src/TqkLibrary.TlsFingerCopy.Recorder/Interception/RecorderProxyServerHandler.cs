using TqkLibrary.Proxy.Handlers;
using TqkLibrary.Proxy.Interfaces;

namespace TqkLibrary.TlsFingerCopy.Recorder.Interception;

/// <summary>
/// Proxy handler that routes every connection through the capturing source and optionally allows loopback targets.
/// </summary>
internal sealed class RecorderProxyServerHandler : BaseProxyServerHandler
{
    private readonly IProxySource _capturingSource;
    private readonly bool _allowLoopback;

    public RecorderProxyServerHandler(IProxySource upstream, IProxySource capturingSource, bool allowLoopback) : base(upstream)
    {
        _capturingSource = capturingSource ?? throw new ArgumentNullException(nameof(capturingSource));
        _allowLoopback = allowLoopback;
    }

    public override Task<bool> IsAcceptDomainAsync(Uri uri, IUserInfo userInfo, CancellationToken cancellationToken = default)
        => _allowLoopback ? Task.FromResult(true) : base.IsAcceptDomainAsync(uri, userInfo, cancellationToken);

    public override Task<IProxySource> GetProxySourceAsync(Uri? uri, IUserInfo userInfo, CancellationToken cancellationToken = default)
        // uri == null is the UDP / bind path: not TLS-over-TCP, so hand out the plain upstream source.
        => Task.FromResult(uri is null ? _proxySource : _capturingSource);
}
