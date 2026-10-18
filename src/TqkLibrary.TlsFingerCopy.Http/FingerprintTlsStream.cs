using System.Buffers;
using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using Org.BouncyCastle.Tls;

namespace TqkLibrary.TlsFingerCopy.Http;

/// <summary>
/// Async TLS client stream over BC <see cref="TlsClientProtocol"/> used in NON-BLOCKING mode: ciphertext is
/// moved between the transport and BC with async I/O, so no thread is blocked while waiting for the network.
/// Supports one concurrent reader plus one concurrent writer (what HTTP/2 needs).
/// </summary>
/// <remarks>
/// <para>Owns the transport stream: disposing this stream disposes it.</para>
/// <para>Locking: a protocol lock guards only the synchronous BC calls (OfferInput / ReadInput /
/// WriteApplicationData / ReadOutput); ciphertext produced by ReadOutput is queued under that lock, so the queue order
/// is the record order. A separate async write lock lets exactly one drainer write the queue to the transport.
/// The reader never waits on the network while holding the protocol lock and never waits for the write lock
/// (output it produces, e.g. a KeyUpdate answer or an alert, is drained in the background or by the writer).</para>
/// <para>Cancellation: ciphertext writes to the transport never take the caller's token (a half written record would
/// corrupt the TLS framing). When the caller's token fires while its data is being written, the stream is faulted and
/// the transport disposed; every later call throws <see cref="IOException"/>.</para>
/// <para>EOF: a transport EOF without close_notify is reported as a normal end of stream (most servers do this).
/// HTTP/1.1 framing (Content-Length / chunked) and HTTP/2 detect truncation; a read-to-EOF body (HTTP/1.0 style, no
/// length) can be silently truncated by an attacker able to close the TCP connection.</para>
/// <para>BC TLS errors (<see cref="TlsFatalAlert"/>, <see cref="TlsFatalAlertReceived"/>, <see cref="TlsException"/>)
/// are rethrown as plain <see cref="IOException"/> (inner preserved) so HTTP stacks classify them as connection errors.</para>
/// <para>Synchronous <see cref="Read(byte[], int, int)"/>, <see cref="Write(byte[], int, int)"/> and <see cref="Flush"/>
/// are sync-over-async wrappers of the async versions (they block a thread).</para>
/// </remarks>
public class FingerprintTlsStream : Stream
{
    private const int TransportBufferSize = 16 * 1024 + 512;
    private static readonly TimeSpan CloseNotifyTimeout = TimeSpan.FromSeconds(1);

    private readonly Stream _transport;
    private readonly TlsClientProtocol _protocol;
    private readonly FingerprintTlsClient _client;
    private readonly object _protocolSync = new();
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private readonly ConcurrentQueue<OutputChunk> _outputQueue = new();
    private readonly byte[] _readBuffer = new byte[TransportBufferSize];
    private bool _inputClosed;
    private int _disposed;
    private Exception? _fault;

    private FingerprintTlsStream(Stream transport, FingerprintTlsClient client)
    {
        _transport = transport;
        _client = client;
        _protocol = new TlsClientProtocol();
    }

    /// <summary>ALPN protocol selected by the server ("h2", "http/1.1"), or null when the server selected none.</summary>
    public string? NegotiatedApplicationProtocol { get; private set; }

    /// <summary>
    /// Runs the TLS handshake over <paramref name="transport"/>. On failure or cancellation the transport is disposed.
    /// </summary>
    public static async Task<FingerprintTlsStream> ConnectAsync(Stream transport, FingerprintTlsClient client, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(transport);
        ArgumentNullException.ThrowIfNull(client);
        var stream = new FingerprintTlsStream(transport, client);
        try
        {
            // Cancellation disposes the transport: pending reads/writes fail, the handshake aborts.
            using (cancellationToken.Register(static s => ((Stream)s!).Dispose(), transport))
            {
                await stream.HandshakeAsync(cancellationToken).ConfigureAwait(false);
            }
            return stream;
        }
        catch (Exception ex)
        {
            await stream.DisposeAsync().ConfigureAwait(false);
            if (cancellationToken.IsCancellationRequested && ex is not OperationCanceledException)
                throw new OperationCanceledException("TLS handshake canceled.", ex, cancellationToken);
            throw;
        }
    }

    private async Task HandshakeAsync(CancellationToken cancellationToken)
    {
        Exception? error = null;
        lock (_protocolSync)
        {
            try
            {
                _protocol.Connect(_client);
            }
            catch (Exception ex)
            {
                error = ex;
            }
            QueueOutputNoThrow();
        }
        await FlushQueuedOutputAsync(error).ConfigureAwait(false);

        while (true)
        {
            lock (_protocolSync)
            {
                if (!_protocol.IsHandshaking) break;
            }
            int read = await _transport.ReadAsync(_readBuffer, cancellationToken).ConfigureAwait(false);
            if (read == 0) throw new IOException("Connection closed by the server during the TLS handshake.");
            lock (_protocolSync)
            {
                try
                {
                    _protocol.OfferInput(_readBuffer, 0, read);
                }
                catch (Exception ex)
                {
                    error = ex;
                }
                QueueOutputNoThrow();
            }
            await FlushQueuedOutputAsync(error).ConfigureAwait(false);
        }
        lock (_protocolSync)
        {
            if (!_protocol.IsConnected) throw new IOException("TLS handshake did not complete.");
        }
        NegotiatedApplicationProtocol = _client.NegotiatedApplicationProtocol;
    }

    /// <summary>Writes the queued output; when <paramref name="error"/> is set, best effort (alert) then rethrows it wrapped.</summary>
    private async Task FlushQueuedOutputAsync(Exception? error)
    {
        if (error is null)
        {
            await DrainOutputAsync(wait: true).ConfigureAwait(false);
            return;
        }
        try
        {
            await DrainOutputAsync(wait: true).ConfigureAwait(false);
        }
        catch
        {
            // best effort: the alert could not be sent
        }
        throw WrapTlsException(error);
    }

    public override bool CanRead => true;
    public override bool CanWrite => true;
    public override bool CanSeek => false;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed != 0, this);
        ThrowIfFaulted();

        while (true)
        {
            lock (_protocolSync)
            {
                int available = _protocol.GetAvailableInputBytes();
                // A zero-byte read waits until plaintext is available (like SslStream), it is not an EOF probe.
                if (available > 0) return buffer.IsEmpty ? 0 : ReadDecrypted(buffer, Math.Min(available, buffer.Length));
                if (_inputClosed || _protocol.IsClosed) return 0;
            }

            // Only one reader at a time touches _readBuffer (Stream contract: no concurrent reads).
            // Canceling a transport read loses no ciphertext: nothing was handed to BC yet.
            int read;
            try
            {
                read = await _transport.ReadAsync(_readBuffer, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                // Abort() may dispose the transport under us; surface every transport failure as IOException.
                if (Volatile.Read(ref _fault) is { } fault) throw new IOException("The TLS connection is faulted.", fault);
                if (ex is IOException) throw;
                throw new IOException("The TLS transport failed.", ex);
            }

            Exception? error = null;
            lock (_protocolSync)
            {
                try
                {
                    if (read == 0)
                    {
                        _inputClosed = true;
                        try
                        {
                            _protocol.CloseInput();
                        }
                        catch (TlsNoCloseNotifyException)
                        {
                            // EOF without close_notify is treated as EOF, see the class remarks (truncation risk).
                        }
                    }
                    else
                    {
                        _protocol.OfferInput(_readBuffer, 0, read);
                    }
                }
                catch (Exception ex)
                {
                    error = ex;
                }
                QueueOutputNoThrow();
            }

            if (error is not null)
            {
                var wrapped = WrapTlsException(error);
                SetFault(wrapped);
                StartBackgroundDrain(); // best effort alert
                throw wrapped;
            }
            if (!_outputQueue.IsEmpty) StartBackgroundDrain();
            if (read == 0) return 0;
        }
    }

    /// <summary>Caller must hold <see cref="_protocolSync"/>.</summary>
    private int ReadDecrypted(Memory<byte> buffer, int count)
    {
        if (MemoryMarshal.TryGetArray<byte>(buffer, out var segment))
            return _protocol.ReadInput(segment.Array!, segment.Offset, count);

        byte[] temp = ArrayPool<byte>.Shared.Rent(count);
        try
        {
            int read = _protocol.ReadInput(temp, 0, count);
            temp.AsSpan(0, read).CopyTo(buffer.Span);
            return read;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(temp);
        }
    }

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed != 0, this);
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfFaulted();
        if (buffer.IsEmpty) return;

        Exception? error = null;
        lock (_protocolSync)
        {
            try
            {
                _protocol.WriteApplicationData(buffer.Span);
            }
            catch (Exception ex)
            {
                error = ex;
            }
            QueueOutputNoThrow();
        }
        if (error is not null)
        {
            var wrapped = WrapTlsException(error);
            SetFault(wrapped);
            StartBackgroundDrain(); // best effort alert
            throw wrapped;
        }
        await DrainCancelableAsync(cancellationToken).ConfigureAwait(false);
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    /// <summary>Sync-over-async: blocks the calling thread.</summary>
    public override int Read(byte[] buffer, int offset, int count)
        => ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

    /// <summary>Sync-over-async: blocks the calling thread.</summary>
    public override void Write(byte[] buffer, int offset, int count)
        => WriteAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

    /// <summary>Waits (through the write lock) until all queued ciphertext has been written and flushed.</summary>
    public override Task FlushAsync(CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed != 0, this);
        return DrainCancelableAsync(cancellationToken);
    }

    /// <summary>Sync-over-async: blocks the calling thread.</summary>
    public override void Flush() => FlushAsync(CancellationToken.None).GetAwaiter().GetResult();

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    /// <summary>Caller must hold <see cref="_protocolSync"/>. Moves BC output into the ordered queue.</summary>
    private void QueueOutputNoThrow()
    {
        try
        {
            int available = _protocol.GetAvailableOutputBytes();
            if (available <= 0) return;
            byte[] chunk = ArrayPool<byte>.Shared.Rent(available);
            int count = _protocol.ReadOutput(chunk, 0, available);
            _outputQueue.Enqueue(new OutputChunk(chunk, count));
        }
        catch
        {
            // nothing to send
        }
    }

    /// <summary>
    /// Drains the queue to the transport, waiting for the write lock first. On caller cancellation the stream is
    /// faulted and the transport disposed (a half written record cannot be resumed).
    /// </summary>
    private async Task DrainCancelableAsync(CancellationToken cancellationToken)
    {
        if (!cancellationToken.CanBeCanceled)
        {
            await DrainOutputAsync(wait: true).ConfigureAwait(false);
            return;
        }
        cancellationToken.ThrowIfCancellationRequested();
        using (cancellationToken.Register(static s => ((FingerprintTlsStream)s!).Abort(), this))
        {
            try
            {
                await DrainOutputAsync(wait: true).ConfigureAwait(false);
            }
            catch (Exception ex) when (cancellationToken.IsCancellationRequested)
            {
                throw new OperationCanceledException("TLS write canceled; the connection was aborted.", ex, cancellationToken);
            }
        }
    }

    /// <summary>
    /// Writes queued ciphertext in queue order. <paramref name="wait"/> = false returns at once when another drainer
    /// holds the write lock (that drainer writes everything queued before it releases, see the re-check below).
    /// </summary>
    private async Task DrainOutputAsync(bool wait)
    {
        while (true)
        {
            if (wait) await _writeLock.WaitAsync().ConfigureAwait(false);
            else if (!_writeLock.Wait(0)) return;
            try
            {
                if (Volatile.Read(ref _fault) is { } fault && _outputQueue.IsEmpty)
                    throw new IOException("The TLS connection is faulted.", fault);
                bool wrote = false;
                while (_outputQueue.TryDequeue(out var chunk))
                {
                    try
                    {
                        // Never the caller's token: see the class remarks.
                        await _transport.WriteAsync(chunk.Buffer.AsMemory(0, chunk.Count), CancellationToken.None).ConfigureAwait(false);
                    }
                    finally
                    {
                        ArrayPool<byte>.Shared.Return(chunk.Buffer);
                    }
                    wrote = true;
                }
                if (wrote) await _transport.FlushAsync(CancellationToken.None).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                if (ex is IOException)
                {
                    SetFault(ex);
                    throw;
                }
                var wrapped = new IOException("Writing to the TLS transport failed.", ex);
                SetFault(wrapped);
                throw wrapped;
            }
            finally
            {
                _writeLock.Release();
            }
            // Output queued after our last TryDequeue while we still held the lock was skipped by its producer.
            if (_outputQueue.IsEmpty) return;
            wait = false;
        }
    }

    private void StartBackgroundDrain() => _ = DrainInBackgroundAsync();

    private async Task DrainInBackgroundAsync()
    {
        try
        {
            await DrainOutputAsync(wait: false).ConfigureAwait(false);
        }
        catch
        {
            // fault recorded by DrainOutputAsync; surfaced by the next Read/Write
        }
    }

    private void SetFault(Exception ex) => Interlocked.CompareExchange(ref _fault, ex, null);

    private void ThrowIfFaulted()
    {
        if (Volatile.Read(ref _fault) is { } fault) throw new IOException("The TLS connection is faulted.", fault);
    }

    /// <summary>Caller canceled during a ciphertext write: the record stream is no longer consistent.</summary>
    private void Abort()
    {
        SetFault(new OperationCanceledException("A TLS write was canceled; the connection was aborted."));
        try
        {
            _transport.Dispose();
        }
        catch
        {
            // ignored: teardown
        }
    }

    private static Exception WrapTlsException(Exception ex) => ex switch
    {
        TlsFatalAlertReceived alert => new IOException($"TLS alert received from the server: {alert.Message}", ex),
        TlsFatalAlert alert => new IOException($"TLS fatal alert: {alert.Message}", ex),
        TlsNoCloseNotifyException => new IOException("TLS connection closed without close_notify.", ex),
        TlsException => new IOException($"TLS error: {ex.Message}", ex),
        _ => ex,
    };

    public override async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        try
        {
            // Best effort close_notify; never wait on a stuck peer.
            if (Volatile.Read(ref _fault) is null && TryCloseProtocol() && _writeLock.Wait(0))
            {
                try
                {
                    using var cts = new CancellationTokenSource(CloseNotifyTimeout);
                    while (_outputQueue.TryDequeue(out var chunk))
                    {
                        try
                        {
                            await _transport.WriteAsync(chunk.Buffer.AsMemory(0, chunk.Count), cts.Token).ConfigureAwait(false);
                        }
                        finally
                        {
                            ArrayPool<byte>.Shared.Return(chunk.Buffer);
                        }
                    }
                    await _transport.FlushAsync(cts.Token).ConfigureAwait(false);
                }
                catch
                {
                    // ignored: connection teardown
                }
                finally
                {
                    _writeLock.Release();
                }
            }
        }
        finally
        {
            await _transport.DisposeAsync().ConfigureAwait(false);
            GC.SuppressFinalize(this);
        }
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing && Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            try
            {
                TryCloseProtocol(); // close_notify is queued but not sent: no blocking write in sync Dispose
            }
            finally
            {
                _transport.Dispose();
            }
        }
        base.Dispose(disposing);
    }

    /// <summary>Queues close_notify; true when there is something to send.</summary>
    private bool TryCloseProtocol()
    {
        lock (_protocolSync)
        {
            try
            {
                if (_protocol.IsClosed || _protocol.IsHandshaking) return false;
                _protocol.Close();
            }
            catch
            {
                // ignored: connection teardown
            }
            QueueOutputNoThrow();
            return !_outputQueue.IsEmpty;
        }
    }

    private readonly record struct OutputChunk(byte[] Buffer, int Count);
}
