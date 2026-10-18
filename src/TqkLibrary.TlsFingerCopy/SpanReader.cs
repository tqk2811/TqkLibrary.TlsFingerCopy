using TqkLibrary.TlsFingerCopy.Exceptions;

namespace TqkLibrary.TlsFingerCopy;

/// <summary>
/// Bounds-checked big-endian reader over a span.
/// </summary>
internal ref struct SpanReader
{
    private readonly ReadOnlySpan<byte> _data;
    private int _pos;

    public SpanReader(ReadOnlySpan<byte> data)
    {
        _data = data;
        _pos = 0;
    }

    public readonly int Remaining => _data.Length - _pos;

    public readonly bool IsEnd => _pos >= _data.Length;

    public byte ReadByte()
    {
        Ensure(1);
        return _data[_pos++];
    }

    public ushort ReadUInt16()
    {
        Ensure(2);
        ushort v = (ushort)((_data[_pos] << 8) | _data[_pos + 1]);
        _pos += 2;
        return v;
    }

    public int ReadUInt24()
    {
        Ensure(3);
        int v = (_data[_pos] << 16) | (_data[_pos + 1] << 8) | _data[_pos + 2];
        _pos += 3;
        return v;
    }

    public ReadOnlySpan<byte> ReadBytes(int count)
    {
        if (count < 0) throw new TlsParseException("Negative length.");
        Ensure(count);
        var slice = _data.Slice(_pos, count);
        _pos += count;
        return slice;
    }

    private readonly void Ensure(int count)
    {
        if (count > _data.Length - _pos)
            throw new TlsParseException($"Unexpected end of data: need {count} bytes, {_data.Length - _pos} remaining.");
    }
}
