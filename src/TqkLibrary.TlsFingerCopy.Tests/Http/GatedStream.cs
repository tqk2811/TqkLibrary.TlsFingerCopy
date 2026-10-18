namespace TqkLibrary.TlsFingerCopy.Tests.Http;

/// <summary>
/// Transport wrapper whose writes can be held: while <see cref="HoldWrites"/> is set, a write sends the first half of
/// its buffer, then waits (honoring the caller's token) until <see cref="ReleaseWrites"/> or Dispose.
/// Simulates a peer that stops reading (TCP backpressure) in the middle of a TLS record.
/// </summary>
internal sealed class GatedStream : Stream
{
    private readonly Stream _inner;
    private readonly TaskCompletionSource _gate = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource _writeHeld = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private volatile bool _hold;

    public GatedStream(Stream inner) => _inner = inner;

    /// <summary>Completes when a write is waiting on the gate.</summary>
    public Task WriteHeld => _writeHeld.Task;

    public void HoldWrites() => _hold = true;

    public void ReleaseWrites()
    {
        _hold = false;
        _gate.TrySetResult();
    }

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        if (_hold)
        {
            int half = buffer.Length / 2;
            await _inner.WriteAsync(buffer[..half], CancellationToken.None);
            await _inner.FlushAsync(CancellationToken.None);
            _writeHeld.TrySetResult();
            await _gate.Task.WaitAsync(cancellationToken);
            buffer = buffer[half..];
        }
        await _inner.WriteAsync(buffer, cancellationToken);
    }

    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        => _inner.ReadAsync(buffer, cancellationToken);

    public override Task FlushAsync(CancellationToken cancellationToken) => _inner.FlushAsync(cancellationToken);

    public override bool CanRead => true;
    public override bool CanWrite => true;
    public override bool CanSeek => false;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
    public override void Flush() => _inner.Flush();
    public override int Read(byte[] buffer, int offset, int count) => _inner.Read(buffer, offset, count);
    public override void Write(byte[] buffer, int offset, int count) => WriteAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _gate.TrySetException(new ObjectDisposedException(nameof(GatedStream)));
            _inner.Dispose();
        }
        base.Dispose(disposing);
    }
}
