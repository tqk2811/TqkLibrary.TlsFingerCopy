namespace TqkLibrary.TlsFingerCopy;

/// <summary>
/// Incrementally assembles a ClientHello handshake message from raw client-to-server bytes
/// (any chunking, possibly spread over several 0x16 records).
/// </summary>
public class TlsRecordReassembler
{
    public const int MaxBufferSize = 64 * 1024;
    private const int MaxRecordLength = 16384 + 2048;

    private readonly List<byte> _raw = new();
    private readonly List<byte> _handshake = new();
    private int _recordOffset;
    private byte[]? _result;

    /// <summary>True when the first byte seen was not 0x16 (not TLS); caller should stop feeding.</summary>
    public bool IsNotTls { get; private set; }

    /// <summary>True when the stream is not a valid/acceptable ClientHello (not TLS, malformed, or over the buffer cap).</summary>
    public bool IsFailed { get; private set; }

    public bool TryFeed(ReadOnlySpan<byte> bytes, out byte[]? handshakeMessage)
    {
        handshakeMessage = null;
        if (_result is not null)
        {
            handshakeMessage = _result;
            return true;
        }
        if (IsFailed) return false;
        if (bytes.IsEmpty && _raw.Count == 0) return false;

        if (_raw.Count + bytes.Length > MaxBufferSize)
        {
            IsFailed = true;
            return false;
        }
        for (int i = 0; i < bytes.Length; i++) _raw.Add(bytes[i]);

        if (_raw[0] != 0x16)
        {
            IsNotTls = true;
            IsFailed = true;
            return false;
        }

        while (_raw.Count - _recordOffset >= 5)
        {
            byte type = _raw[_recordOffset];
            int length = (_raw[_recordOffset + 3] << 8) | _raw[_recordOffset + 4];
            if (type != 0x16 || _raw[_recordOffset + 1] != 0x03 || length == 0 || length > MaxRecordLength)
            {
                IsFailed = true;
                return false;
            }
            if (_raw.Count - _recordOffset < 5 + length) break;

            _handshake.AddRange(_raw.GetRange(_recordOffset + 5, length));
            _recordOffset += 5 + length;

            if (_handshake.Count >= 4)
            {
                if (_handshake[0] != 0x01)
                {
                    IsFailed = true;
                    return false;
                }
                int total = 4 + ((_handshake[1] << 16) | (_handshake[2] << 8) | _handshake[3]);
                if (_handshake.Count >= total)
                {
                    _result = _handshake.GetRange(0, total).ToArray();
                    handshakeMessage = _result;
                    return true;
                }
            }
        }
        return false;
    }
}
