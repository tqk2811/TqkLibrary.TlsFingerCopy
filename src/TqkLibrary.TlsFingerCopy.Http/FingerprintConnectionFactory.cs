using System.Net;
using System.Net.Sockets;
using TqkLibrary.TlsFingerCopy.Http.Exceptions;

namespace TqkLibrary.TlsFingerCopy.Http;

/// <summary>
/// Opens TLS connections whose ClientHello reproduces the configured fingerprint.
/// </summary>
/// <remarks>
/// <see cref="ConnectCallbackAsync"/> plugs into <see cref="SocketsHttpHandler.ConnectCallback"/> of a handler
/// built by the user. That handler must send https requests as http:// with the original Host header
/// (see <see cref="FingerprintHttpMessageHandler"/>, which does all of this) and must use
/// Version20 + RequestVersionExact for HTTP/2 connections (h2 "prior knowledge" over the TLS stream).
/// </remarks>
public class FingerprintConnectionFactory
{
    private readonly FingerprintHttpHandlerOptions _options;
    private readonly AlpnProtocolCache _alpnCache = new();

    public FingerprintConnectionFactory(FingerprintHttpHandlerOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(options.Fingerprint);
        _options = options;
    }

    /// <summary>True when the fingerprint's ALPN offers "h2".</summary>
    public bool OffersHttp2 => _options.Fingerprint.Alpn.Contains("h2");

    /// <summary>Whether the last handshake with host:port negotiated h2; null when unknown.</summary>
    public bool? GetKnownHttp2(string host, int port) => _alpnCache.TryGetIsHttp2(host, port);

    /// <summary>TCP (or <see cref="FingerprintHttpHandlerOptions.TransportFactory"/>) + TLS handshake, bounded by ConnectTimeout.</summary>
    public async Task<FingerprintTlsStream> ConnectAsync(string host, int port, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(host);
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        if (_options.ConnectTimeout != Timeout.InfiniteTimeSpan) timeoutCts.CancelAfter(_options.ConnectTimeout);
        try
        {
            Stream transport = _options.TransportFactory is null
                ? await ConnectTcpAsync(host, port, timeoutCts.Token).ConfigureAwait(false)
                : await _options.TransportFactory(host, port, timeoutCts.Token).ConfigureAwait(false);

            FingerprintTlsClient client;
            try
            {
                client = new FingerprintTlsClient(_options.Fingerprint, host, _options.CertificateValidationCallback);
            }
            catch
            {
                await transport.DisposeAsync().ConfigureAwait(false);
                throw;
            }
            // From here the TLS stream owns the transport (disposed by ConnectAsync on failure).
            var stream = await FingerprintTlsStream.ConnectAsync(transport, client, timeoutCts.Token).ConfigureAwait(false);
            _alpnCache.Set(host, port, stream.NegotiatedApplicationProtocol == "h2");
            return stream;
        }
        catch (OperationCanceledException ex) when (!cancellationToken.IsCancellationRequested && timeoutCts.IsCancellationRequested)
        {
            throw new TimeoutException($"Connecting to {host}:{port} timed out after {_options.ConnectTimeout}.", ex);
        }
    }

    /// <summary>
    /// <see cref="SocketsHttpHandler.ConnectCallback"/> implementation. Throws <see cref="AlpnMismatchException"/>
    /// when the negotiated ALPN does not match the HTTP version of the pool's request (the result is cached,
    /// see <see cref="GetKnownHttp2"/>, so a retry with the right version succeeds). The exception is raised while
    /// connecting, before any request byte is written, so retrying the request is always safe.
    /// </summary>
    public async ValueTask<Stream> ConnectCallbackAsync(SocketsHttpConnectionContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        string host = context.DnsEndPoint.Host;
        int port = context.DnsEndPoint.Port;
        bool wantHttp2 = context.InitialRequestMessage.Version.Major >= 2;

        var stream = await ConnectAsync(host, port, cancellationToken).ConfigureAwait(false);
        bool isHttp2 = stream.NegotiatedApplicationProtocol == "h2";
        if (isHttp2 != wantHttp2)
        {
            string? negotiated = stream.NegotiatedApplicationProtocol;
            await stream.DisposeAsync().ConfigureAwait(false);
            throw new AlpnMismatchException(host, port, wantHttp2, negotiated);
        }
        return stream;
    }

    private static async Task<Stream> ConnectTcpAsync(string host, int port, CancellationToken cancellationToken)
    {
        var socket = new Socket(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        try
        {
            await socket.ConnectAsync(new DnsEndPoint(host.Trim('[', ']'), port), cancellationToken).ConfigureAwait(false);
            return new NetworkStream(socket, ownsSocket: true);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }
}
