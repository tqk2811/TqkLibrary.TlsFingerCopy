using System.Collections.Concurrent;

namespace TqkLibrary.TlsFingerCopy.Http;

/// <summary>
/// Remembers, per authority (host:port), whether the last TLS handshake negotiated HTTP/2.
/// </summary>
internal class AlpnProtocolCache
{
    private readonly ConcurrentDictionary<string, bool> _isHttp2 = new(StringComparer.OrdinalIgnoreCase);

    public bool? TryGetIsHttp2(string host, int port) => _isHttp2.TryGetValue(Key(host, port), out bool value) ? value : null;

    public void Set(string host, int port, bool isHttp2) => _isHttp2[Key(host, port)] = isHttp2;

    private static string Key(string host, int port) => $"{host.Trim('[', ']')}:{port}";
}
