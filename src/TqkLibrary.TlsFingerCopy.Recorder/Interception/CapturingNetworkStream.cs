using System.Net.Sockets;
using TqkLibrary.TlsFingerCopy.Models;

namespace TqkLibrary.TlsFingerCopy.Recorder.Interception;

/// <summary>
/// Same job as <see cref="CapturingStream"/> but for an upstream <see cref="NetworkStream"/>: it IS a
/// <see cref="NetworkStream"/> over the same socket, so the proxy library can still half-close it
/// (<c>Socket.Shutdown(Send)</c>) and the server sees the client's FIN. Reads go straight to the socket;
/// writes go to the socket first and are inspected afterwards.
/// Ownership: the socket is not owned by the base stream; disposing this stream disposes the original
/// inner stream (which owns the socket).
/// </summary>
internal sealed class CapturingNetworkStream : NetworkStream
{
    private readonly NetworkStream _inner;
    private readonly ClientHelloInspector _inspector;

    public CapturingNetworkStream(NetworkStream inner, Action<ClientHelloInfo> onCaptured)
        : base((inner ?? throw new ArgumentNullException(nameof(inner))).Socket, ownsSocket: false)
    {
        _inner = inner;
        _inspector = new ClientHelloInspector(onCaptured);
    }

    public override void Write(byte[] buffer, int offset, int count)
    {
        base.Write(buffer, offset, count);
        _inspector.Inspect(buffer.AsSpan(offset, count));
    }

    public override void Write(ReadOnlySpan<byte> buffer)
    {
        base.Write(buffer);
        _inspector.Inspect(buffer);
    }

    public override async Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        await base.WriteAsync(buffer, offset, count, cancellationToken).ConfigureAwait(false);
        _inspector.Inspect(buffer.AsSpan(offset, count));
    }

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        await base.WriteAsync(buffer, cancellationToken).ConfigureAwait(false);
        _inspector.Inspect(buffer.Span);
    }

    // APM path: route through WriteAsync so the bytes are inspected too.
    public override IAsyncResult BeginWrite(byte[] buffer, int offset, int count, AsyncCallback? callback, object? state)
        => System.Threading.Tasks.TaskToAsyncResult.Begin(WriteAsync(buffer, offset, count, CancellationToken.None), callback, state);

    public override void EndWrite(IAsyncResult asyncResult)
        => System.Threading.Tasks.TaskToAsyncResult.End(asyncResult);

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (disposing) _inner.Dispose();
    }
}
