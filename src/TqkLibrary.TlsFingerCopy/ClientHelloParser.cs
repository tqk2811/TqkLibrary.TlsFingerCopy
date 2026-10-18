using TqkLibrary.TlsFingerCopy.Exceptions;
using TqkLibrary.TlsFingerCopy.Models;

namespace TqkLibrary.TlsFingerCopy;

/// <summary>
/// Parses a TLS ClientHello from a record stream (starting with 0x16) or a bare handshake message (starting with 0x01).
/// </summary>
public class ClientHelloParser
{
    private const int MaxRecordLength = 16384 + 2048;

    public ClientHelloInfo Parse(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty) throw new TlsParseException("Empty input.");

        ushort recordVersion = 0;
        byte[] handshake;
        if (data[0] == 0x16) handshake = ReassembleRecords(data, out recordVersion);
        else if (data[0] == 0x01) handshake = ExtractHandshake(data);
        else throw new TlsParseException($"Unexpected first byte 0x{data[0]:x2}; expected 0x16 or 0x01.");

        return ParseHandshake(handshake, recordVersion);
    }

    private static byte[] ReassembleRecords(ReadOnlySpan<byte> data, out ushort recordVersion)
    {
        recordVersion = 0;
        var fragments = new List<byte>();
        var reader = new SpanReader(data);
        bool first = true;
        while (!reader.IsEnd)
        {
            byte type = reader.ReadByte();
            ushort version = reader.ReadUInt16();
            ushort length = reader.ReadUInt16();
            if (type != 0x16) throw new TlsParseException($"Unexpected record type 0x{type:x2}.");
            if ((version >> 8) != 0x03) throw new TlsParseException($"Unsupported record version 0x{version:x4}.");
            if (length == 0 || length > MaxRecordLength) throw new TlsParseException($"Invalid record length {length}.");
            if (first)
            {
                recordVersion = version;
                first = false;
            }
            fragments.AddRange(reader.ReadBytes(length).ToArray());

            if (fragments.Count >= 4)
            {
                if (fragments[0] != 0x01) throw new TlsParseException("Handshake message is not a ClientHello.");
                int total = 4 + ((fragments[1] << 16) | (fragments[2] << 8) | fragments[3]);
                if (fragments.Count >= total) return fragments.GetRange(0, total).ToArray();
            }
        }
        throw new TlsParseException("Incomplete ClientHello in record stream.");
    }

    private static byte[] ExtractHandshake(ReadOnlySpan<byte> data)
    {
        var reader = new SpanReader(data);
        byte type = reader.ReadByte();
        if (type != 0x01) throw new TlsParseException("Handshake message is not a ClientHello.");
        int length = reader.ReadUInt24();
        if (length > reader.Remaining) throw new TlsParseException("Handshake length exceeds available data.");
        return data.Slice(0, 4 + length).ToArray();
    }

    private static ClientHelloInfo ParseHandshake(byte[] handshake, ushort recordVersion)
    {
        var info = new ClientHelloInfo { RecordVersion = recordVersion, RawHandshake = handshake };
        var reader = new SpanReader(handshake.AsSpan(4));

        info.LegacyVersion = reader.ReadUInt16();
        info.Random = reader.ReadBytes(32).ToArray();
        int sessionIdLength = reader.ReadByte();
        if (sessionIdLength > 32) throw new TlsParseException($"Session id length {sessionIdLength} exceeds 32.");
        info.SessionId = reader.ReadBytes(sessionIdLength).ToArray();

        int cipherLen = reader.ReadUInt16();
        if ((cipherLen & 1) != 0) throw new TlsParseException("Cipher suites length is odd.");
        var ciphers = new SpanReader(reader.ReadBytes(cipherLen));
        while (!ciphers.IsEnd) info.CipherSuites.Add(ciphers.ReadUInt16());

        var compression = reader.ReadBytes(reader.ReadByte());
        foreach (byte b in compression) info.CompressionMethods.Add(b);

        if (reader.IsEnd) return info;

        int extLen = reader.ReadUInt16();
        if (extLen != reader.Remaining) throw new TlsParseException("Extensions length does not match remaining data.");
        var exts = new SpanReader(reader.ReadBytes(extLen));
        while (!exts.IsEnd)
        {
            ushort type = exts.ReadUInt16();
            var extData = exts.ReadBytes(exts.ReadUInt16());
            info.Extensions.Add(new TlsExtensionEntry { Type = type, DataHex = Convert.ToHexString(extData).ToLowerInvariant() });
            DecodeExtension(info, type, extData);
        }
        return info;
    }

    private static void DecodeExtension(ClientHelloInfo info, ushort type, ReadOnlySpan<byte> data)
    {
        switch (type)
        {
            case 0:
                DecodeServerName(info, data);
                break;
            case 10:
                info.SupportedGroups = ReadU16List(data);
                break;
            case 11:
                info.EcPointFormats = new List<byte>(ReadLengthPrefixedBytes(data).ToArray());
                break;
            case 13:
                info.SignatureAlgorithms = ReadU16List(data);
                break;
            case 16:
                DecodeAlpn(info, data);
                break;
            case 21:
                info.PaddingLength = data.Length;
                break;
            case 27:
                info.CertCompressionAlgorithms = ReadU16List(data, oneByteLength: true);
                break;
            case 34:
                info.DelegatedCredentialSigAlgs = ReadU16List(data);
                break;
            case 41:
                info.HasPreSharedKey = true;
                break;
            case 43:
                info.SupportedVersions = ReadU16List(data, oneByteLength: true);
                break;
            case 45:
                info.PskKeyExchangeModes = new List<byte>(ReadLengthPrefixedBytes(data).ToArray());
                break;
            case 51:
                DecodeKeyShare(info, data);
                break;
        }
    }

    private static ReadOnlySpan<byte> ReadLengthPrefixedBytes(ReadOnlySpan<byte> data)
    {
        var reader = new SpanReader(data);
        var list = reader.ReadBytes(reader.ReadByte());
        if (!reader.IsEnd) throw new TlsParseException("Trailing bytes in extension.");
        return list;
    }

    private static List<ushort> ReadU16List(ReadOnlySpan<byte> data, bool oneByteLength = false)
    {
        var reader = new SpanReader(data);
        int len = oneByteLength ? reader.ReadByte() : reader.ReadUInt16();
        if ((len & 1) != 0) throw new TlsParseException("Odd length of 16-bit list.");
        var items = new SpanReader(reader.ReadBytes(len));
        if (!reader.IsEnd) throw new TlsParseException("Trailing bytes in extension.");
        var result = new List<ushort>();
        while (!items.IsEnd) result.Add(items.ReadUInt16());
        return result;
    }

    private static void DecodeServerName(ClientHelloInfo info, ReadOnlySpan<byte> data)
    {
        var reader = new SpanReader(data);
        var list = new SpanReader(reader.ReadBytes(reader.ReadUInt16()));
        if (!reader.IsEnd) throw new TlsParseException("Trailing bytes in server_name extension.");
        while (!list.IsEnd)
        {
            byte nameType = list.ReadByte();
            var name = list.ReadBytes(list.ReadUInt16());
            if (nameType == 0 && info.ServerName is null)
                info.ServerName = System.Text.Encoding.ASCII.GetString(name);
        }
    }

    private static void DecodeAlpn(ClientHelloInfo info, ReadOnlySpan<byte> data)
    {
        var reader = new SpanReader(data);
        var list = new SpanReader(reader.ReadBytes(reader.ReadUInt16()));
        if (!reader.IsEnd) throw new TlsParseException("Trailing bytes in ALPN extension.");
        while (!list.IsEnd)
        {
            var proto = list.ReadBytes(list.ReadByte());
            info.AlpnRaw.Add(proto.ToArray());
            info.Alpn.Add(System.Text.Encoding.ASCII.GetString(proto));
        }
    }

    private static void DecodeKeyShare(ClientHelloInfo info, ReadOnlySpan<byte> data)
    {
        var reader = new SpanReader(data);
        var list = new SpanReader(reader.ReadBytes(reader.ReadUInt16()));
        if (!reader.IsEnd) throw new TlsParseException("Trailing bytes in key_share extension.");
        while (!list.IsEnd)
        {
            ushort group = list.ReadUInt16();
            list.ReadBytes(list.ReadUInt16());
            info.KeyShareGroups.Add(group);
        }
    }
}
