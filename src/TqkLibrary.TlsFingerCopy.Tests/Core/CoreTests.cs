using TqkLibrary.TlsFingerCopy.Exceptions;
using TqkLibrary.TlsFingerCopy.Helpers;
using TqkLibrary.TlsFingerCopy.Models;

namespace TqkLibrary.TlsFingerCopy.Tests.Core;

[TestClass]
public class CoreTests
{
    private readonly ClientHelloParser _parser = new();

    [TestMethod]
    public void Grease_Detection()
    {
        Assert.IsTrue(GreaseHelper.IsGrease(0x0a0a));
        Assert.IsTrue(GreaseHelper.IsGrease(0xfafa));
        Assert.IsTrue(GreaseHelper.IsGrease(0x7a7a));
        Assert.IsFalse(GreaseHelper.IsGrease(0x1301));
        Assert.IsFalse(GreaseHelper.IsGrease(0x0a1a));
        Assert.IsFalse(GreaseHelper.IsGrease(0x0000));
    }

    [TestMethod]
    public void Parse_Records_ReadsAllFields()
    {
        byte[] bytes = ClientHelloBuilder.Chrome().BuildRecords();
        ClientHelloInfo info = _parser.Parse(bytes);

        Assert.AreEqual((ushort)0x0301, info.RecordVersion);
        Assert.AreEqual((ushort)0x0303, info.LegacyVersion);
        Assert.HasCount(32, info.Random);
        Assert.HasCount(32, info.SessionId);
        Assert.HasCount(10, info.CipherSuites);
        Assert.AreEqual((ushort)0x0a0a, info.CipherSuites[0]);
        Assert.AreEqual((ushort)0x1301, info.CipherSuites[1]);
        CollectionAssert.AreEqual(new byte[] { 0 }, info.CompressionMethods);
        Assert.HasCount(12, info.Extensions);
        Assert.AreEqual((ushort)0x0a0a, info.Extensions[0].Type);
        Assert.AreEqual((ushort)0, info.Extensions[1].Type);
        Assert.AreEqual("example.com", info.ServerName);
        CollectionAssert.AreEqual(new ushort[] { 0x1a1a, 0x001d, 0x0017, 0x0018 }, info.SupportedGroups);
        CollectionAssert.AreEqual(new byte[] { 0 }, info.EcPointFormats);
        Assert.HasCount(8, info.SignatureAlgorithms);
        CollectionAssert.AreEqual(new[] { "h2", "http/1.1" }, info.Alpn);
        CollectionAssert.AreEqual(new ushort[] { 0x1a1a, 0x0304, 0x0303 }, info.SupportedVersions);
        CollectionAssert.AreEqual(new ushort[] { 0x1a1a, 0x001d }, info.KeyShareGroups);
        CollectionAssert.AreEqual(new byte[] { 1 }, info.PskKeyExchangeModes);
        CollectionAssert.AreEqual(new ushort[] { 2 }, info.CertCompressionAlgorithms);
        Assert.IsFalse(info.HasPreSharedKey);
        Assert.AreEqual(10, info.PaddingLength);
        Assert.AreEqual((byte)1, info.RawHandshake[0]);
        Assert.HasCount(bytes.Length - 5, info.RawHandshake);
    }

    [TestMethod]
    public void Parse_BareHandshake_RecordVersionZero()
    {
        byte[] handshake = ClientHelloBuilder.Chrome().BuildHandshake();
        ClientHelloInfo info = _parser.Parse(handshake);
        Assert.AreEqual((ushort)0, info.RecordVersion);
        Assert.AreEqual("example.com", info.ServerName);
        CollectionAssert.AreEqual(handshake, info.RawHandshake);
    }

    [TestMethod]
    public void Parse_SpanningTwoRecords()
    {
        var builder = ClientHelloBuilder.Chrome();
        byte[] handshake = builder.BuildHandshake();
        byte[] bytes = builder.BuildRecords(maxFragment: 100);
        Assert.IsGreaterThan(5 + handshake.Length, bytes.Length);

        ClientHelloInfo info = _parser.Parse(bytes);
        CollectionAssert.AreEqual(handshake, info.RawHandshake);
        Assert.AreEqual("example.com", info.ServerName);
    }

    [TestMethod]
    public void Parse_Malformed_Throws()
    {
        byte[] good = ClientHelloBuilder.Chrome().BuildRecords();

        Assert.ThrowsExactly<TlsParseException>(() => _parser.Parse(Array.Empty<byte>()));
        Assert.ThrowsExactly<TlsParseException>(() => _parser.Parse(new byte[] { 0x17, 3, 3, 0, 1, 0 }));
        Assert.ThrowsExactly<TlsParseException>(() => _parser.Parse(good.AsSpan(0, good.Length - 1).ToArray()));

        // Corrupt the extensions length (bare handshake) so it no longer matches.
        byte[] hs = ClientHelloBuilder.Chrome().BuildHandshake();
        int extLenOffset = 4 + 2 + 32 + 1 + 32 + 2 + 20 + 2;
        hs[extLenOffset + 1]++;
        Assert.ThrowsExactly<TlsParseException>(() => _parser.Parse(hs));

        // Odd cipher-suite length.
        byte[] hs2 = ClientHelloBuilder.Chrome().BuildHandshake();
        hs2[4 + 2 + 32 + 1 + 32 + 1]++;
        Assert.ThrowsExactly<TlsParseException>(() => _parser.Parse(hs2));

        // Handshake claims more bytes than provided.
        byte[] hs3 = ClientHelloBuilder.Chrome().BuildHandshake();
        hs3[3] += 5;
        Assert.ThrowsExactly<TlsParseException>(() => _parser.Parse(hs3));
    }

    [TestMethod]
    public void Reassembler_OneByteChunks()
    {
        var builder = ClientHelloBuilder.Chrome();
        byte[] bytes = builder.BuildRecords(maxFragment: 120);
        var reassembler = new TlsRecordReassembler();
        byte[]? message = null;
        int completedAt = -1;
        for (int i = 0; i < bytes.Length; i++)
        {
            if (reassembler.TryFeed(bytes.AsSpan(i, 1), out message))
            {
                completedAt = i;
                break;
            }
        }
        Assert.AreEqual(bytes.Length - 1, completedAt);
        Assert.IsNotNull(message);
        CollectionAssert.AreEqual(builder.BuildHandshake(), message);
        Assert.IsFalse(reassembler.IsNotTls);
    }

    [TestMethod]
    public void Reassembler_NotTls()
    {
        var reassembler = new TlsRecordReassembler();
        Assert.IsFalse(reassembler.TryFeed("GET / HTTP/1.1\r\n"u8, out byte[]? message));
        Assert.IsNull(message);
        Assert.IsTrue(reassembler.IsNotTls);
    }

    [TestMethod]
    public void Reassembler_CapsBuffer()
    {
        var reassembler = new TlsRecordReassembler();
        // Valid-looking record header announcing a big record, then flood.
        Assert.IsFalse(reassembler.TryFeed(new byte[] { 0x16, 3, 1, 0x40, 0x00 }, out _));
        byte[] chunk = new byte[16 * 1024];
        for (int i = 0; i < 6; i++) reassembler.TryFeed(chunk, out _);
        Assert.IsTrue(reassembler.IsFailed);
    }

    [TestMethod]
    public void Ja3_HandComputed()
    {
        var builder = new ClientHelloBuilder();
        builder.CipherSuites.AddRange(new ushort[] { 0x0a0a, 0x1301, 0xc02b });
        builder.AddExtension(0, ClientHelloBuilder.Sni("a.test"));
        builder.AddExtension(10, ClientHelloBuilder.SupportedGroups(0x001d, 0x0017));
        builder.AddExtension(11, ClientHelloBuilder.EcPointFormats(0));
        ClientHelloInfo info = _parser.Parse(builder.BuildRecords());

        // 0x0303=771; ciphers 0x1301=4865, 0xc02b=49195 (GREASE dropped); exts 0,10,11; groups 0x1d=29, 0x17=23; formats 0.
        string expected = "771,4865-49195,0-10-11,29-23,0";
        var calc = new Ja3Calculator();
        Assert.AreEqual(expected, calc.BuildString(info));
        // md5 computed independently with md5sum.
        Assert.AreEqual("3e916670429427a5a33c947802616cdc", calc.ComputeHash(info));
    }

    [TestMethod]
    public void Ja4_HandComputed()
    {
        var builder = new ClientHelloBuilder();
        builder.CipherSuites.AddRange(new ushort[] { 0x0a0a, 0x1301, 0xc02b });
        builder.AddExtension(0, ClientHelloBuilder.Sni("a.test"));
        builder.AddExtension(10, ClientHelloBuilder.SupportedGroups(0x001d));
        builder.AddExtension(11, ClientHelloBuilder.EcPointFormats(0));
        builder.AddExtension(16, ClientHelloBuilder.Alpn("h2"));
        builder.AddExtension(13, ClientHelloBuilder.SigAlgs(0x0403, 0x0804));
        builder.AddExtension(43, ClientHelloBuilder.SupportedVersions(0x0a0a, 0x0304));
        ClientHelloInfo info = _parser.Parse(builder.BuildRecords());

        // a: t + 13 (highest non-GREASE supported version 0x0304) + d (SNI) + 02 ciphers + 06 exts (0,10,11,16,13,43) + h2
        // b: sha256("1301,c02b")[..12] = 777cda164f4b (sha256sum)
        // c: sha256("000a,000b,000d,002b_0403,0804")[..12] = fb71836bce29 (sha256sum; SNI and ALPN excluded, exts sorted)
        Assert.AreEqual("t13d0206h2_777cda164f4b_fb71836bce29", new Ja4Calculator().Compute(info));
    }

    [TestMethod]
    public void Ja4_NoSniNoAlpn_UsesLegacyVersion()
    {
        var builder = new ClientHelloBuilder();
        builder.CipherSuites.Add(0x1301);
        builder.AddExtension(10, ClientHelloBuilder.SupportedGroups(0x001d));
        ClientHelloInfo info = _parser.Parse(builder.BuildHandshake());
        string ja4 = new Ja4Calculator().Compute(info);
        Assert.StartsWith("t12i010100_", ja4);
    }

    [TestMethod]
    public void Merger_DetectsRandomizedOrder()
    {
        var a = ClientHelloBuilder.Chrome(greaseA: 0x0a0a, greaseB: 0x1a1a);
        var b = ClientHelloBuilder.Chrome(greaseA: 0x2a2a, greaseB: 0x3a3a);
        var c = ClientHelloBuilder.Chrome(greaseA: 0x4a4a, greaseB: 0x5a5a);
        // Same extensions, same order but different GREASE values: not randomized.
        var merger = new FingerprintMerger();
        TlsFingerprint stable = merger.Merge(new[] { _parser.Parse(a.BuildHandshake()), _parser.Parse(b.BuildHandshake()) }, "chrome", "test");
        Assert.IsFalse(stable.ExtensionOrderRandomized);
        Assert.IsTrue(stable.UsesGrease);
        Assert.AreEqual(2, stable.SampleCount);
        Assert.AreEqual("chrome", stable.Name);

        // Shuffle order in the third sample.
        c.Extensions.Reverse();
        TlsFingerprint randomized = merger.Merge(new[] { _parser.Parse(a.BuildHandshake()), _parser.Parse(c.BuildHandshake()) });
        Assert.IsTrue(randomized.ExtensionOrderRandomized);
        Assert.AreEqual(2, randomized.SampleCount);
    }

    [TestMethod]
    public void Merger_DifferentExtensionSet_Throws()
    {
        var a = ClientHelloBuilder.Chrome();
        var b = ClientHelloBuilder.Chrome();
        b.Extensions.RemoveAt(b.Extensions.Count - 1);
        var merger = new FingerprintMerger();
        var samples = new[] { _parser.Parse(a.BuildHandshake()), _parser.Parse(b.BuildHandshake()) };
        Assert.ThrowsExactly<ArgumentException>(() => merger.Merge(samples));
    }

    [TestMethod]
    public async Task File_SaveLoad_Roundtrip()
    {
        ClientHelloInfo info = _parser.Parse(ClientHelloBuilder.Chrome().BuildRecords());
        TlsFingerprint fingerprint = new TlsFingerprintFactory().Create(info, "chrome", "chrome.exe");
        string dir = Path.Combine(Path.GetTempPath(), "TlsFingerCopyTests_" + Guid.NewGuid().ToString("N"));
        string path = Path.Combine(dir, "fp.json");
        try
        {
            var file = new TlsFingerprintFile();
            await file.SaveAsync(fingerprint, path, CancellationToken.None);
            TlsFingerprint loaded = await file.LoadAsync(path, CancellationToken.None);

            Assert.AreEqual(1, loaded.FormatVersion);
            Assert.AreEqual("chrome", loaded.Name);
            Assert.AreEqual("chrome.exe", loaded.Source);
            Assert.AreEqual(fingerprint.RecordedAt, loaded.RecordedAt);
            Assert.AreEqual("example.com", loaded.ServerName);
            CollectionAssert.AreEqual(fingerprint.CipherSuites, loaded.CipherSuites);
            Assert.HasCount(fingerprint.Extensions.Count, loaded.Extensions);
            Assert.AreEqual(fingerprint.Extensions[3].DataHex, loaded.Extensions[3].DataHex);
            CollectionAssert.AreEqual(fingerprint.Alpn, loaded.Alpn);
            Assert.AreEqual(fingerprint.Ja3, loaded.Ja3);
            Assert.AreEqual(fingerprint.Ja3Hash, loaded.Ja3Hash);
            Assert.AreEqual(fingerprint.Ja4, loaded.Ja4);
            Assert.AreEqual(fingerprint.RawClientHelloHex, loaded.RawClientHelloHex);
            Assert.IsTrue(loaded.UsesGrease);
            Assert.Contains("\"cipherSuites\"", await File.ReadAllTextAsync(path));
        }
        finally
        {
            if (Directory.Exists(dir)) Directory.Delete(dir, true);
        }
    }

    private static ClientHelloBuilder WithKeyShareAndResumption()
    {
        var b = ClientHelloBuilder.Chrome();
        int index = b.Extensions.FindIndex(x => x.Type == 51);
        byte[] key = Enumerable.Repeat((byte)0xaa, 32).ToArray();
        byte[] share = ClientHelloBuilder.U16Prefixed(ClientHelloBuilder.Concat(
            ClientHelloBuilder.U16(0x001d), ClientHelloBuilder.U16Prefixed(key)));
        b.Extensions[index] = (51, share);
        return b;
    }

    [TestMethod]
    public void Factory_StoresRecordVersionAndSessionIdLength()
    {
        var factory = new TlsFingerprintFactory();
        TlsFingerprint fromRecords = factory.Create(_parser.Parse(ClientHelloBuilder.Chrome().BuildRecords()));
        Assert.AreEqual((ushort)0x0301, fromRecords.RecordVersion);
        Assert.AreEqual(32, fromRecords.SessionIdLength);
        Assert.IsTrue(fromRecords.HasPaddingExtension);

        var empty = ClientHelloBuilder.Chrome();
        empty.SessionId = Array.Empty<byte>();
        TlsFingerprint bare = factory.Create(_parser.Parse(empty.BuildHandshake()));
        Assert.AreEqual((ushort)0, bare.RecordVersion);
        Assert.AreEqual(0, bare.SessionIdLength);
    }

    [TestMethod]
    public void Factory_ZeroesKeyShareKeepingGroupsAndLengths()
    {
        ClientHelloInfo info = _parser.Parse(WithKeyShareAndResumption().BuildHandshake());
        TlsFingerprint fp = new TlsFingerprintFactory().Create(info);

        string expected = "0024" + "001d" + "0020" + new string('0', 64);
        Assert.AreEqual(expected, fp.Extensions.Single(x => x.Type == 51).DataHex);
        Assert.Contains("aaaaaaaa", info.Extensions.Single(x => x.Type == 51).DataHex);
        CollectionAssert.AreEqual(new ushort[] { 0x001d }, fp.KeyShareGroups);
    }

    [TestMethod]
    public void Factory_ZeroesEchPayloadKeepingLength()
    {
        var b = ClientHelloBuilder.Chrome();
        b.AddExtension(0xfe0d, Enumerable.Repeat((byte)0x5c, 20).ToArray());
        TlsFingerprint fp = new TlsFingerprintFactory().Create(_parser.Parse(b.BuildHandshake()));
        Assert.AreEqual(new string('0', 40), fp.Extensions.Single(x => x.Type == 0xfe0d).DataHex);
    }

    [TestMethod]
    public void Factory_ExcludesPskAndEarlyData()
    {
        var b = ClientHelloBuilder.Chrome();
        b.AddExtension(42, Array.Empty<byte>());
        b.AddExtension(41, new byte[] { 0, 3, 1, 2, 3, 0, 0, 0, 0, 0, 1, 0xff });
        ClientHelloInfo info = _parser.Parse(b.BuildHandshake());
        TlsFingerprint fp = new TlsFingerprintFactory().Create(info);

        Assert.IsTrue(fp.HadPreSharedKey);
        Assert.IsFalse(fp.Extensions.Any(x => x.Type == 41 || x.Type == 42));
        Assert.HasCount(12, fp.Extensions);
        Assert.IsTrue(info.Extensions.Any(x => x.Type == 41));

        TlsFingerprint plain = new TlsFingerprintFactory().Create(_parser.Parse(ClientHelloBuilder.Chrome().BuildHandshake()));
        Assert.IsFalse(plain.HadPreSharedKey);
    }

    [TestMethod]
    public void Merger_IgnoresPskDifference_AndPrefersNonPskBase()
    {
        var withPsk = ClientHelloBuilder.Chrome();
        withPsk.AddExtension(41, new byte[] { 0, 3, 1, 2, 3, 0, 0, 0, 0, 0, 1, 0xff });
        var plain = ClientHelloBuilder.Chrome();
        TlsFingerprint fp = new FingerprintMerger().Merge(new[]
        {
            _parser.Parse(withPsk.BuildHandshake()),
            _parser.Parse(plain.BuildHandshake()),
        });
        Assert.AreEqual(2, fp.SampleCount);
        Assert.IsFalse(fp.HadPreSharedKey);
        Assert.IsFalse(fp.ExtensionOrderRandomized);
    }

    [TestMethod]
    public void Merger_DifferentCipherList_Throws()
    {
        var a = ClientHelloBuilder.Chrome();
        var b = ClientHelloBuilder.Chrome();
        b.CipherSuites.Add(0x009c);
        var samples = new[] { _parser.Parse(a.BuildHandshake()), _parser.Parse(b.BuildHandshake()) };
        var ex = Assert.ThrowsExactly<ArgumentException>(() => new FingerprintMerger().Merge(samples));
        Assert.Contains("cipher suites", ex.Message);
    }

    [TestMethod]
    public void Ja4_NonAsciiAlpn_UsesHexOfFirstAndLastByte()
    {
        var builder = new ClientHelloBuilder();
        builder.CipherSuites.Add(0x1301);
        builder.AddExtension(16, ClientHelloBuilder.U16Prefixed(ClientHelloBuilder.U8Prefixed(new byte[] { 0xab, 0xcd })));
        ClientHelloInfo info = _parser.Parse(builder.BuildHandshake());
        // first char of "ab" = a, last char of "cd" = d
        Assert.StartsWith("t12i0101ad_", new Ja4Calculator().Compute(info));
    }

    [TestMethod]
    public void Ja4_CPartEmptyHash_WhenOnlySniAlpnGreaseExtensions()
    {
        var info = new ClientHelloInfo { LegacyVersion = 0x0303, ServerName = "a.test" };
        info.CipherSuites.Add(0x1301);
        info.Extensions.Add(new TlsExtensionEntry { Type = 0x0a0a });
        info.Extensions.Add(new TlsExtensionEntry { Type = 0 });
        info.Extensions.Add(new TlsExtensionEntry { Type = 16 });
        info.Alpn.Add("h2");
        info.SignatureAlgorithms.AddRange(new ushort[] { 0x0403, 0x0804 });
        Assert.EndsWith("_000000000000", new Ja4Calculator().Compute(info));
    }

    [TestMethod]
    public void Parser_RejectsRecordMajorVersionNotThree()
    {
        byte[] bytes = ClientHelloBuilder.Chrome().BuildRecords(recordVersion: 0x0201);
        Assert.ThrowsExactly<TlsParseException>(() => _parser.Parse(bytes));

        var reassembler = new TlsRecordReassembler();
        Assert.IsFalse(reassembler.TryFeed(bytes, out _));
        Assert.IsTrue(reassembler.IsFailed);
    }

    [TestMethod]
    public void Parser_RejectsSessionIdLongerThan32()
    {
        var b = ClientHelloBuilder.Chrome();
        b.SessionId = new byte[33];
        Assert.ThrowsExactly<TlsParseException>(() => _parser.Parse(b.BuildHandshake()));
    }
}
