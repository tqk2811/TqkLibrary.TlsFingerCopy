using System.Net;
using Microsoft.Extensions.Logging;
using TqkLibrary.Proxy.Handlers;
using TqkLibrary.Proxy.Interfaces;
using TqkLibrary.Proxy.ProxyServers;
using TqkLibrary.Proxy.StreamHelpers;
using TqkLibrary.TlsFingerCopy.Recorder.Enums;

namespace TqkLibrary.TlsFingerCopy.Recorder.Interception;

/// <summary>
/// Pins the accepted protocol to <see cref="RecorderProxyType"/> instead of the library's auto-detection.
/// </summary>
internal sealed class RecorderPreProxyServerHandler : BasePreProxyServerHandler
{
    private readonly RecorderProxyType _type;

    public RecorderPreProxyServerHandler(RecorderProxyType type, ILoggerFactory? loggerFactory) : base(loggerFactory)
    {
        _type = type;
    }

    public override Task<IProxyServer> GetProxyServerAsync(PreReadStream preReadStream, IPEndPoint iPEndPoint, Guid tunnelId, CancellationToken cancellationToken = default)
    {
        IProxyServer server = _type switch
        {
            RecorderProxyType.Socks5 => new Socks5ProxyServer(_loggerFactory),
            RecorderProxyType.Socks4 => new Socks4ProxyServer(_loggerFactory),
            RecorderProxyType.Http => new HttpProxyServer(_loggerFactory),
            _ => throw new NotSupportedException(_type.ToString()),
        };
        return Task.FromResult(server);
    }
}
