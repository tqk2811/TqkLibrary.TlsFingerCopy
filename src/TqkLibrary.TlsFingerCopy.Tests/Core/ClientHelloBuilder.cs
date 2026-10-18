namespace TqkLibrary.TlsFingerCopy.Tests.Core;

/// <summary>
/// Builds valid TLS ClientHello wire bytes for tests.
/// </summary>
public class ClientHelloBuilder
{
    public ushort LegacyVersion { get; set; } = 0x0303;

    public byte[] Random { get; set; } = Enumerable.Range(0, 32).Select(x => (byte)x).ToArray();

    public byte[] SessionId { get; set; } = Enumerable.Range(100, 32).Select(x => (byte)x).ToArray();

    public List<ushort> CipherSuites { get; } = new();

    public List<(ushort Type, byte[] Data)> Extensions { get; } = new();

    public static byte[] U16(ushort v) => new[] { (byte)(v >> 8), (byte)v };

    public static byte[] Concat(params byte[][] parts) => parts.SelectMany(x => x).ToArray();

    public static byte[] U16Prefixed(byte[] data) => Concat(U16((ushort)data.Length), data);

    public static byte[] U8Prefixed(byte[] data) => Concat(new[] { (byte)data.Length }, data);

    public static byte[] U16Items(params ushort[] items) => Concat(items.Select(U16).ToArray());

    public static byte[] Sni(string host)
    {
        byte[] name = System.Text.Encoding.ASCII.GetBytes(host);
        byte[] entry = Concat(new byte[] { 0 }, U16Prefixed(name));
        return U16Prefixed(entry);
    }

    public static byte[] Alpn(params string[] protocols)
        => U16Prefixed(Concat(protocols.Select(p => U8Prefixed(System.Text.Encoding.ASCII.GetBytes(p))).ToArray()));

    public static byte[] SupportedGroups(params ushort[] groups) => U16Prefixed(U16Items(groups));

    public static byte[] SigAlgs(params ushort[] algs) => U16Prefixed(U16Items(algs));

    public static byte[] SupportedVersions(params ushort[] versions) => U8Prefixed(U16Items(versions));

    public static byte[] EcPointFormats(params byte[] formats) => U8Prefixed(formats);

    public static byte[] KeyShare(params (ushort Group, int KeyLength)[] shares)
        => U16Prefixed(Concat(shares.Select(s => Concat(U16(s.Group), U16Prefixed(new byte[s.KeyLength]))).ToArray()));

    public ClientHelloBuilder AddExtension(ushort type, byte[] data)
    {
        Extensions.Add((type, data));
        return this;
    }

    /// <summary>Chrome-like ClientHello with GREASE, SNI, ALPN, supported_versions, key_share, sig algs.</summary>
    public static ClientHelloBuilder Chrome(string host = "example.com", ushort greaseA = 0x0a0a, ushort greaseB = 0x1a1a)
    {
        var b = new ClientHelloBuilder();
        b.CipherSuites.AddRange(new ushort[] { greaseA, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8 });
        b.AddExtension(greaseA, Array.Empty<byte>());
        b.AddExtension(0, Sni(host));
        b.AddExtension(10, SupportedGroups(greaseB, 0x001d, 0x0017, 0x0018));
        b.AddExtension(11, EcPointFormats(0));
        b.AddExtension(13, SigAlgs(0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601));
        b.AddExtension(16, Alpn("h2", "http/1.1"));
        b.AddExtension(27, U8Prefixed(U16Items(2)));
        b.AddExtension(43, SupportedVersions(greaseB, 0x0304, 0x0303));
        b.AddExtension(45, U8Prefixed(new byte[] { 1 }));
        b.AddExtension(51, KeyShare((greaseB, 1), (0x001d, 32)));
        b.AddExtension(greaseB, new byte[] { 0 });
        b.AddExtension(21, new byte[10]);
        return b;
    }

    public byte[] BuildHandshake()
    {
        byte[] ciphers = U16Prefixed(U16Items(CipherSuites.ToArray()));
        byte[] extensions = U16Prefixed(Concat(Extensions.Select(e => Concat(U16(e.Type), U16Prefixed(e.Data))).ToArray()));
        byte[] body = Concat(
            U16(LegacyVersion),
            Random,
            U8Prefixed(SessionId),
            ciphers,
            U8Prefixed(new byte[] { 0 }),
            extensions);
        return Concat(new byte[] { 1, (byte)(body.Length >> 16), (byte)(body.Length >> 8), (byte)body.Length }, body);
    }

    /// <summary>Wraps the handshake in TLS records, each carrying at most <paramref name="maxFragment"/> bytes.</summary>
    public byte[] BuildRecords(int maxFragment = 16384, ushort recordVersion = 0x0301)
    {
        byte[] handshake = BuildHandshake();
        var result = new List<byte>();
        for (int offset = 0; offset < handshake.Length; offset += maxFragment)
        {
            int len = Math.Min(maxFragment, handshake.Length - offset);
            result.Add(0x16);
            result.AddRange(U16(recordVersion));
            result.AddRange(U16((ushort)len));
            result.AddRange(handshake.AsSpan(offset, len).ToArray());
        }
        return result.ToArray();
    }
}
