using System.Net;
using Microsoft.Extensions.Logging;
using TqkLibrary.Proxy;
using TqkLibrary.Proxy.Interfaces;
using TqkLibrary.Proxy.ProxySources;
using TqkLibrary.TlsFingerCopy.Models;
using TqkLibrary.TlsFingerCopy.Recorder.Interception;
using TqkLibrary.TlsFingerCopy.Recorder.Models;

namespace TqkLibrary.TlsFingerCopy.Recorder;

/// <summary>
/// Local proxy (SOCKS5 / HTTP CONNECT / SOCKS4) that records the TLS ClientHello of every TCP connection
/// passing through it. Traffic is forwarded byte-for-byte; capturing is a read-only tee of the
/// client-to-server direction. Samples are grouped per <c>ServerName ?? target host</c> in <see cref="Session"/>
/// and saved as merged fingerprint files by <see cref="SaveAllAsync"/> / <see cref="StopAsync"/>.
/// Ownership: the recorder owns its proxy server and upstream source; the options' logger factory is borrowed.
/// </summary>
public class FingerprintRecorder : IAsyncDisposable
{
    private readonly RecorderOptions _options;
    private readonly ILogger? _logger;
    private readonly object _stateLock = new();
    private readonly LocalProxySource _upstream;
    private ProxyServer? _server;
    private bool _stopped;
    private volatile bool _stopping;

    public FingerprintRecorder(RecorderOptions options)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        ArgumentNullException.ThrowIfNull(options.ListenEndPoint);
        ArgumentException.ThrowIfNullOrEmpty(options.OutputDirectory);
        _logger = options.LoggerFactory?.CreateLogger<FingerprintRecorder>();
        _upstream = new LocalProxySource(options.LoggerFactory);
        RunDirectory = Path.Combine(options.OutputDirectory, DateTime.Now.ToString("yyyyMMdd-HHmmss", System.Globalization.CultureInfo.InvariantCulture));
    }

    /// <summary>
    /// Per-run directory (<c>&lt;OutputDirectory&gt;/yyyyMMdd-HHmmss</c>) all files of this recorder are written to.
    /// Created on first save; <see cref="SaveAllAsync"/> and <see cref="StopAsync"/> reuse it, so files are only
    /// overwritten within the same run and never clobber an earlier run.
    /// </summary>
    public string RunDirectory { get; }

    /// <summary>Samples captured so far.</summary>
    public CaptureSession Session { get; } = new();

    /// <summary>Actual listen endpoint after <see cref="Start"/> (useful when the configured port was 0); null before.</summary>
    public IPEndPoint? LocalEndPoint => _server?.IPEndPoint;

    /// <summary>
    /// Raised once per connection when a ClientHello was captured. Runs synchronously on the connection's
    /// forwarding thread after the bytes were already sent, so keep handlers short. Exceptions are swallowed.
    /// </summary>
    public event EventHandler<ClientHelloCapturedEventArgs>? ClientHelloCaptured;

    public void Start()
    {
        lock (_stateLock)
        {
            if (_stopped) throw new ObjectDisposedException(nameof(FingerprintRecorder));
            if (_server is not null) throw new InvalidOperationException("Recorder is already started.");

            var capturingSource = new CapturingProxySource(_upstream, OnCaptured);
            var handler = new RecorderProxyServerHandler(_upstream, capturingSource, _options.AllowLoopbackTargets);
            var server = new ProxyServer(_options.ListenEndPoint, handler, _options.LoggerFactory)
            {
                PreProxyServerHandler = new RecorderPreProxyServerHandler(_options.ProxyType, _options.LoggerFactory),
            };
            server.StartListen();
            _server = server;
        }
        _logger?.LogInformation("Recorder listening on {EndPoint} ({Type})", LocalEndPoint, _options.ProxyType);
    }

    /// <summary>Stops listening, drops open connections and saves all captured fingerprints. Idempotent. Once stopping begins, new
    /// captures are ignored (not added to <see cref="Session"/>, no <see cref="ClientHelloCaptured"/> event).</summary>
    /// <returns>Paths of the files written (empty when already stopped).</returns>
    public async Task<IReadOnlyList<string>> StopAsync(CancellationToken cancellationToken = default)
    {
        ProxyServer? server;
        lock (_stateLock)
        {
            if (_stopped) return Array.Empty<string>();
            _stopped = true;
            _stopping = true;
            server = _server;
            _server = null;
        }
        server?.Dispose();
        await _upstream.DisposeAsync().ConfigureAwait(false);
        return await SaveAllAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Writes one merged fingerprint file per capture group into the output directory.</summary>
    public Task<IReadOnlyList<string>> SaveAllAsync(CancellationToken cancellationToken = default)
        => Session.SaveAsync(RunDirectory, _options.Source, cancellationToken);

    public async ValueTask DisposeAsync()
    {
        await StopAsync().ConfigureAwait(false);
        GC.SuppressFinalize(this);
    }

    private void OnCaptured(Uri target, ClientHelloInfo info)
    {
        if (_stopping) return; // late connections racing with StopAsync are dropped
        string key = Session.Add(info, target.Host);
        var args = new ClientHelloCapturedEventArgs
        {
            Target = target,
            Key = key,
            ClientHello = info,
            CapturedAt = DateTimeOffset.UtcNow,
        };
        try
        {
            ClientHelloCaptured?.Invoke(this, args);
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "ClientHelloCaptured handler threw");
        }
    }
}
