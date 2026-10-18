using System.Net;
using System.Net.Sockets;
using TqkLibrary.TlsFingerCopy.Http.Exceptions;

namespace TqkLibrary.TlsFingerCopy.Http;

/// <summary>
/// Primary HTTP handler whose TLS ClientHello reproduces a recorded fingerprint.
/// </summary>
/// <remarks>
/// <para>How: an https request is sent through an inner <see cref="SocketsHttpHandler"/> as http://host:port with the
/// original Host header; its ConnectCallback opens TCP + <see cref="FingerprintTlsStream"/>, so the handler writes
/// plain HTTP into our TLS stream. The request URI is restored before returning, so
/// <see cref="HttpResponseMessage.RequestMessage"/> still shows https. Plain http requests go through a second,
/// ordinary inner handler (separate connection pool).</para>
/// <para>HTTP version: the version is chosen by ALPN like a browser does, not by <see cref="HttpRequestMessage.Version"/>.
/// The ALPN list is sent exactly as recorded. Per authority the last negotiated protocol is cached; when unknown,
/// HTTP/2 is assumed if the fingerprint offers "h2". On a mismatch the connection is dropped
/// (<see cref="AlpnMismatchException"/>, raised while connecting, before anything is sent) and the request is retried
/// (at most <see cref="MaxAlpnRetries"/> times, concurrent first requests to a new authority can each hit a mismatch)
/// with the version now in the cache.</para>
/// <para>Cookies and redirects are disabled inside (UseCookies = false, AllowAutoRedirect = false, forced back even if
/// <see cref="FingerprintHttpHandlerOptions.ConfigureHandler"/> changes them): handle them in an outer
/// <see cref="DelegatingHandler"/> chained BEFORE this handler, which sees the real https URI. ConfigureHandler enabling a
/// proxy or replacing ConnectCallback makes the constructor throw <see cref="InvalidOperationException"/>.</para>
/// <para>Limit: only the TLS layer is copied; HTTP/2 SETTINGS / header order still come from .NET.</para>
/// </remarks>
public class FingerprintHttpMessageHandler : HttpMessageHandler
{
    /// <summary>How many times one request is resent after an <see cref="AlpnMismatchException"/>.</summary>
    public const int MaxAlpnRetries = 2;

    private readonly FingerprintHttpHandlerOptions _options;
    private readonly FingerprintConnectionFactory _factory;
    private readonly SocketsHttpHandler _tlsHandler;
    private readonly SocketsHttpHandler _plainHandler;
    private readonly HttpMessageInvoker _tlsInvoker;
    private readonly HttpMessageInvoker _plainInvoker;

    public FingerprintHttpMessageHandler(FingerprintHttpHandlerOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        _factory = new FingerprintConnectionFactory(options);

        _options = options;
        _tlsHandler = CreateInnerHandler(options, _factory.ConnectCallbackAsync);
        _plainHandler = CreateInnerHandler(options, ConnectPlainAsync);

        _tlsInvoker = new HttpMessageInvoker(_tlsHandler, disposeHandler: false);
        _plainInvoker = new HttpMessageInvoker(_plainHandler, disposeHandler: false);
    }

    /// <summary>The connection factory, usable to open raw fingerprinted TLS streams.</summary>
    public FingerprintConnectionFactory ConnectionFactory => _factory;

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        Uri? original = request.RequestUri;
        if (original is null || !original.IsAbsoluteUri) throw new InvalidOperationException("Request URI must be absolute.");

        if (original.Scheme == Uri.UriSchemeHttp)
            return await _plainInvoker.SendAsync(request, cancellationToken).ConfigureAwait(false);
        if (original.Scheme != Uri.UriSchemeHttps)
            throw new NotSupportedException($"Scheme '{original.Scheme}' is not supported.");

        Version originalVersion = request.Version;
        HttpVersionPolicy originalPolicy = request.VersionPolicy;
        bool addedHost = false;
        try
        {
            if (request.Headers.Host is null)
            {
                request.Headers.Host = original.IsDefaultPort ? original.IdnHost : $"{original.IdnHost}:{original.Port}";
                addedHost = true;
            }
            request.RequestUri = new UriBuilder(original) { Scheme = Uri.UriSchemeHttp, Port = original.Port }.Uri;
            request.VersionPolicy = HttpVersionPolicy.RequestVersionExact;

            string host = request.RequestUri.IdnHost;
            bool useHttp2 = _factory.GetKnownHttp2(host, original.Port) ?? _factory.OffersHttp2;
            for (int attempt = 0; ; attempt++)
            {
                request.Version = useHttp2 ? HttpVersion.Version20 : HttpVersion.Version11;
                try
                {
                    return await _tlsInvoker.SendAsync(request, cancellationToken).ConfigureAwait(false);
                }
                catch (HttpRequestException ex) when (attempt < MaxAlpnRetries && FindAlpnMismatch(ex) is { } mismatch)
                {
                    // Safe to resend: AlpnMismatchException is only thrown by ConnectCallback, before the request
                    // (and its content) is written. Prefer the cache: a concurrent request may have updated it.
                    useHttp2 = _factory.GetKnownHttp2(host, original.Port) ?? mismatch.NegotiatedHttp2;
                }
            }
        }
        finally
        {
            request.RequestUri = original;
            request.Version = originalVersion;
            request.VersionPolicy = originalPolicy;
            if (addedHost) request.Headers.Host = null;
        }
    }

    protected override HttpResponseMessage Send(HttpRequestMessage request, CancellationToken cancellationToken)
        => SendAsync(request, cancellationToken).GetAwaiter().GetResult();

    private static AlpnMismatchException? FindAlpnMismatch(Exception? ex)
    {
        for (; ex is not null; ex = ex.InnerException)
        {
            if (ex is AlpnMismatchException mismatch) return mismatch;
        }
        return null;
    }

    private async ValueTask<Stream> ConnectPlainAsync(SocketsHttpConnectionContext context, CancellationToken cancellationToken)
    {
        if (_options.TransportFactory is not null)
            return await _options.TransportFactory(context.DnsEndPoint.Host, context.DnsEndPoint.Port, cancellationToken).ConfigureAwait(false);

        var socket = new Socket(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        try
        {
            await socket.ConnectAsync(context.DnsEndPoint, cancellationToken).ConfigureAwait(false);
            return new NetworkStream(socket, ownsSocket: true);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Builds an inner handler, lets <see cref="FingerprintHttpHandlerOptions.ConfigureHandler"/> tune it, then enforces
    /// the settings this handler depends on: changing UseProxy / Proxy / ConnectCallback throws
    /// <see cref="InvalidOperationException"/>; UseCookies and AllowAutoRedirect are forced back to false.
    /// </summary>
    private static SocketsHttpHandler CreateInnerHandler(
        FingerprintHttpHandlerOptions options,
        Func<SocketsHttpConnectionContext, CancellationToken, ValueTask<Stream>> connectCallback)
    {
        var handler = new SocketsHttpHandler
        {
            UseProxy = false,
            UseCookies = false,
            AllowAutoRedirect = false,
            AutomaticDecompression = options.AutomaticDecompression,
            PooledConnectionLifetime = options.PooledConnectionLifetime,
            ConnectTimeout = options.ConnectTimeout,
            EnableMultipleHttp2Connections = true,
            ConnectCallback = connectCallback,
        };
        try
        {
            options.ConfigureHandler?.Invoke(handler);
            if (handler.UseProxy || handler.Proxy is not null)
                throw new InvalidOperationException(
                    "ConfigureHandler must not enable a proxy on the inner handler (it would bypass the fingerprinted TLS); use FingerprintHttpHandlerOptions.TransportFactory instead.");
            if (!ReferenceEquals(handler.ConnectCallback, connectCallback))
                throw new InvalidOperationException(
                    "ConfigureHandler must not replace ConnectCallback of the inner handler; use FingerprintHttpHandlerOptions.TransportFactory instead.");
            handler.UseCookies = false;
            handler.AllowAutoRedirect = false;
            return handler;
        }
        catch
        {
            handler.Dispose();
            throw;
        }
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _tlsInvoker.Dispose();
            _plainInvoker.Dispose();
            _tlsHandler.Dispose();
            _plainHandler.Dispose();
        }
        base.Dispose(disposing);
    }
}
