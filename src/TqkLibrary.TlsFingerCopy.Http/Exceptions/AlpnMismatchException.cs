namespace TqkLibrary.TlsFingerCopy.Http.Exceptions;

/// <summary>
/// The server negotiated an ALPN protocol different from the HTTP version the connection was opened for
/// (e.g. "h2" for an HTTP/1.1 request). The connection is discarded; retrying with <see cref="NegotiatedHttp2"/>
/// as the HTTP version succeeds. <see cref="FingerprintHttpMessageHandler"/> retries automatically.
/// </summary>
public class AlpnMismatchException : IOException
{
    public AlpnMismatchException(string host, int port, bool requestedHttp2, string? negotiatedProtocol)
        : base($"{host}:{port} negotiated ALPN '{negotiatedProtocol ?? "(none)"}' but the connection was opened for {(requestedHttp2 ? "HTTP/2" : "HTTP/1.1")}.")
    {
        Host = host;
        Port = port;
        RequestedHttp2 = requestedHttp2;
        NegotiatedProtocol = negotiatedProtocol;
    }

    public string Host { get; }

    public int Port { get; }

    public bool RequestedHttp2 { get; }

    /// <summary>ALPN chosen by the server, null when it chose none (= HTTP/1.1).</summary>
    public string? NegotiatedProtocol { get; }

    public bool NegotiatedHttp2 => NegotiatedProtocol == "h2";
}
