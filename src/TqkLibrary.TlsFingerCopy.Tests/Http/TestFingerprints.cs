using TqkLibrary.TlsFingerCopy.Models;
using TqkLibrary.TlsFingerCopy.Tests.Core;
using static TqkLibrary.TlsFingerCopy.Tests.Core.ClientHelloBuilder;

namespace TqkLibrary.TlsFingerCopy.Tests.Http;

/// <summary>
/// Fingerprints built from synthetic ClientHellos shaped like recent Chrome (13x: X25519MLKEM768, ALPS 17613, GREASE ECH).
/// </summary>
internal static class TestFingerprints
{
    public static TlsFingerprint Chrome(bool randomized)
    {
        var b = new ClientHelloBuilder();
        b.CipherSuites.AddRange(new ushort[] { 0x3a3a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035 });
        b.AddExtension(0x3a3a, Array.Empty<byte>());
        b.AddExtension(0, Sni("recorded.example"));
        b.AddExtension(23, Array.Empty<byte>());
        b.AddExtension(65281, new byte[] { 0 });
        b.AddExtension(10, SupportedGroups(0x6a6a, 0x11ec, 0x001d, 0x0017, 0x0018));
        b.AddExtension(11, EcPointFormats(0));
        b.AddExtension(35, Array.Empty<byte>());
        b.AddExtension(16, Alpn("h2", "http/1.1"));
        b.AddExtension(5, new byte[] { 1, 0, 0, 0, 0 });
        b.AddExtension(13, SigAlgs(0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601));
        b.AddExtension(18, Array.Empty<byte>());
        b.AddExtension(51, KeyShare((0x6a6a, 1), (0x11ec, 1216), (0x001d, 32)));
        b.AddExtension(45, U8Prefixed(new byte[] { 1 }));
        b.AddExtension(43, SupportedVersions(0x7a7a, 0x0304, 0x0303));
        b.AddExtension(27, U8Prefixed(U16Items(2)));
        b.AddExtension(17613, U16Prefixed(U8Prefixed("h2"u8.ToArray())));
        b.AddExtension(0xfe0d, Concat(new byte[] { 0, 0, 1, 0, 1, 0x55 }, U16Prefixed(new byte[32]), U16Prefixed(new byte[144])));
        b.AddExtension(0x8a8a, new byte[] { 0 });
        return Create(b, randomized);
    }

    /// <summary>Small Chrome-like hello (x25519 only) whose length falls in BoringSSL's padding window.</summary>
    public static TlsFingerprint SmallWithPadding()
        => Create(ClientHelloBuilder.Chrome("recorded.example"), randomized: false);

    private static TlsFingerprint Create(ClientHelloBuilder builder, bool randomized)
    {
        var info = new ClientHelloParser().Parse(builder.BuildRecords());
        var fingerprint = new TlsFingerprintFactory().Create(info, "test-chrome");
        fingerprint.ExtensionOrderRandomized = randomized;
        return fingerprint;
    }
}
