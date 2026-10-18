using TqkLibrary.TlsFingerCopy.Models;

namespace TqkLibrary.TlsFingerCopy.Recorder.Models;

/// <summary>
/// Data of <see cref="FingerprintRecorder.ClientHelloCaptured"/>.
/// </summary>
public class ClientHelloCapturedEventArgs : EventArgs
{
    /// <summary>Target the client asked the proxy to connect to (host may be an IP address).</summary>
    public required Uri Target { get; init; }

    /// <summary>Target host as sent to the proxy.</summary>
    public string TargetHost => Target.Host;

    /// <summary>Target port as sent to the proxy.</summary>
    public int TargetPort => Target.Port;

    /// <summary>SNI of the ClientHello, null when absent.</summary>
    public string? ServerName => ClientHello.ServerName;

    /// <summary>Group key the sample was stored under (<c>ServerName ?? TargetHost</c>).</summary>
    public required string Key { get; init; }

    public required ClientHelloInfo ClientHello { get; init; }

    public required DateTimeOffset CapturedAt { get; init; }
}
