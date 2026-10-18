using System.Net;
using Microsoft.Extensions.Logging;
using TqkLibrary.TlsFingerCopy.Recorder.Enums;

namespace TqkLibrary.TlsFingerCopy.Recorder.Models;

/// <summary>
/// Settings of a <see cref="FingerprintRecorder"/>.
/// </summary>
public class RecorderOptions
{
    /// <summary>Local endpoint the proxy listens on. Port 0 picks a free port (see <see cref="FingerprintRecorder.LocalEndPoint"/>).</summary>
    public required IPEndPoint ListenEndPoint { get; set; }

    /// <summary>Proxy protocol accepted from clients.</summary>
    public RecorderProxyType ProxyType { get; set; } = RecorderProxyType.Socks5;

    /// <summary>Base directory; each recorder run writes into its own <c>yyyyMMdd-HHmmss</c> subfolder of it (see <see cref="FingerprintRecorder.RunDirectory"/>).</summary>
    public required string OutputDirectory { get; set; }

    /// <summary>Free-text label stored in <c>TlsFingerprint.Source</c> (application name, etc.).</summary>
    public string? Source { get; set; }

    /// <summary>
    /// Allow targets on loopback (localhost, 127.0.0.1, ::1). The underlying proxy library rejects them
    /// by default; only tests normally need this.
    /// </summary>
    public bool AllowLoopbackTargets { get; set; }

    /// <summary>Optional logger factory, passed to the proxy library. Not owned by the recorder.</summary>
    public ILoggerFactory? LoggerFactory { get; set; }
}
