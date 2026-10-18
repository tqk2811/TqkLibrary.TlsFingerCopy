using TqkLibrary.TlsFingerCopy.Exceptions;
using TqkLibrary.TlsFingerCopy.Models;

namespace TqkLibrary.TlsFingerCopy.Recorder.Interception;

/// <summary>
/// Feeds forwarded client-to-server bytes to a <see cref="TlsRecordReassembler"/> until a ClientHello is
/// captured or the traffic turns out not to be one, then stops inspecting. Never throws: the data was
/// already forwarded and must keep flowing. Shared by <see cref="CapturingStream"/> and
/// <see cref="CapturingNetworkStream"/>. Not thread-safe (one writer per connection).
/// </summary>
internal sealed class ClientHelloInspector
{
    private readonly Action<ClientHelloInfo> _onCaptured;
    private readonly ClientHelloParser _parser = new();
    private TlsRecordReassembler? _reassembler = new();

    public ClientHelloInspector(Action<ClientHelloInfo> onCaptured)
    {
        _onCaptured = onCaptured ?? throw new ArgumentNullException(nameof(onCaptured));
    }

    public void Inspect(ReadOnlySpan<byte> bytes)
    {
        TlsRecordReassembler? reassembler = _reassembler;
        if (reassembler is null || bytes.IsEmpty) return;
        try
        {
            if (reassembler.TryFeed(bytes, out byte[]? handshake))
            {
                _reassembler = null;
                ClientHelloInfo info = _parser.Parse(handshake!);
                _onCaptured(info);
            }
            else if (reassembler.IsFailed)
            {
                _reassembler = null;
            }
        }
        catch (TlsParseException)
        {
            _reassembler = null;
        }
        catch (Exception)
        {
            // Includes handler failures.
            _reassembler = null;
        }
    }
}
