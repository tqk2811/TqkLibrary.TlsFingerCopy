using System.Net.Sockets;
using TqkLibrary.TlsFingerCopy.Helpers;
using TqkLibrary.TlsFingerCopy.Http;
using TqkLibrary.TlsFingerCopy.Models;

namespace TqkLibrary.TlsFingerCopy.Tests.Http;

/// <summary>
/// Offline: the ClientHello actually sent by <see cref="FingerprintConnectionFactory"/> matches the fingerprint.
/// </summary>
[TestClass]
public sealed class ClientHelloReplayTests
{
    private const ushort GreaseMarker = 0x0a0a;

    [TestMethod]
    public async Task Replay_FixedOrder_MatchesFingerprint()
    {
        TlsFingerprint fingerprint = TestFingerprints.Chrome(randomized: false);
        ClientHelloInfo sent = await CaptureAsync(fingerprint, "www.example.com");

        CollectionAssert.AreEqual(Normalize(fingerprint.CipherSuites), Normalize(sent.CipherSuites));
        CollectionAssert.AreEqual(Normalize(fingerprint.Extensions.Select(x => x.Type)), Normalize(sent.Extensions.Select(x => x.Type)));
        CollectionAssert.AreEqual(Normalize(fingerprint.SupportedGroups), Normalize(sent.SupportedGroups));
        CollectionAssert.AreEqual(Normalize(fingerprint.KeyShareGroups), Normalize(sent.KeyShareGroups));
        CollectionAssert.AreEqual(Normalize(fingerprint.SignatureAlgorithms), Normalize(sent.SignatureAlgorithms));
        CollectionAssert.AreEqual(Normalize(fingerprint.SupportedVersions), Normalize(sent.SupportedVersions));
        CollectionAssert.AreEqual(fingerprint.Alpn, sent.Alpn);
        CollectionAssert.AreEqual(fingerprint.PskKeyExchangeModes, sent.PskKeyExchangeModes);
        CollectionAssert.AreEqual(fingerprint.CertCompressionAlgorithms, sent.CertCompressionAlgorithms);
        Assert.AreEqual(fingerprint.RecordVersion, sent.RecordVersion);
        Assert.AreEqual(fingerprint.LegacyVersion, sent.LegacyVersion);
        Assert.AreEqual(fingerprint.SessionIdLength, sent.SessionId.Length);
        Assert.AreEqual("www.example.com", sent.ServerName);
        Assert.AreEqual(fingerprint.Ja4, new Ja4Calculator().Compute(sent));
        Assert.AreEqual(fingerprint.Ja3Hash, new Ja3Calculator().ComputeHash(sent));

        // Same extension data where it is not per-connection
        foreach (ushort type in new ushort[] { 5, 11, 13, 16, 27, 45, 17613, 65281 })
        {
            Assert.AreEqual(
                fingerprint.Extensions.Single(x => x.Type == type).DataHex,
                sent.Extensions.Single(x => x.Type == type).DataHex,
                $"extension {type}");
        }

        // Real key shares: GREASE 1 byte, MLKEM hybrid 1216, x25519 32 (non-zero)
        byte[] keyShare = Convert.FromHexString(sent.Extensions.Single(x => x.Type == 51).DataHex);
        Assert.AreEqual(2 + (4 + 1) + (4 + 1216) + (4 + 32), keyShare.Length);
        Assert.IsTrue(keyShare.Skip(2 + 5 + 4).Take(1216).Any(x => x != 0));

        // ECH GREASE keeps the recorded header (cipher suite, lengths), config_id / enc / payload refreshed
        byte[] recordedEch = Convert.FromHexString(fingerprint.Extensions.Single(x => x.Type == 0xfe0d).DataHex);
        byte[] ech = Convert.FromHexString(sent.Extensions.Single(x => x.Type == 0xfe0d).DataHex);
        Assert.HasCount(recordedEch.Length, ech);
        int encLength = (recordedEch[6] << 8) | recordedEch[7];
        int payloadLengthPos = 8 + encLength;
        CollectionAssert.AreEqual(recordedEch.Take(5).ToArray(), ech.Take(5).ToArray(), "type + kdf + aead");
        CollectionAssert.AreEqual(recordedEch.Skip(6).Take(2).ToArray(), ech.Skip(6).Take(2).ToArray(), "enc length");
        CollectionAssert.AreEqual(
            recordedEch.Skip(payloadLengthPos).Take(2).ToArray(), ech.Skip(payloadLengthPos).Take(2).ToArray(), "payload length");
        Assert.IsTrue(ech.Skip(8).Take(encLength).Any(x => x != 0), "enc randomized");
        Assert.IsTrue(ech.Skip(payloadLengthPos + 2).Any(x => x != 0), "payload randomized");
    }

    [TestMethod]
    public async Task Replay_EchFreshPerConnection()
    {
        TlsFingerprint fingerprint = TestFingerprints.Chrome(randomized: false);
        string first = (await CaptureAsync(fingerprint, "www.example.com")).Extensions.Single(x => x.Type == 0xfe0d).DataHex;
        string second = (await CaptureAsync(fingerprint, "www.example.com")).Extensions.Single(x => x.Type == 0xfe0d).DataHex;
        Assert.AreNotEqual(first, second);
        Assert.AreEqual(first[..10], second[..10]); // type + cipher suite unchanged
    }

    [TestMethod]
    public async Task Replay_UnparsableEch_IsDropped()
    {
        TlsFingerprint fingerprint = TestFingerprints.Chrome(randomized: false);
        fingerprint.Extensions.Single(x => x.Type == 0xfe0d).DataHex = "00000100"; // too short for an ECH outer
        ClientHelloInfo sent = await CaptureAsync(fingerprint, "www.example.com");
        Assert.IsFalse(sent.Extensions.Any(x => x.Type == 0xfe0d));
    }

    [TestMethod]
    public async Task Replay_SessionTicketEmptyAndCookieDropped()
    {
        TlsFingerprint fingerprint = TestFingerprints.Chrome(randomized: false);
        fingerprint.Extensions.Single(x => x.Type == 35).DataHex = "0102030405";
        fingerprint.Extensions.Insert(5, new TlsExtensionEntry { Type = 44, DataHex = "0002abcd" });
        ClientHelloInfo sent = await CaptureAsync(fingerprint, "www.example.com");
        Assert.AreEqual(string.Empty, sent.Extensions.Single(x => x.Type == 35).DataHex);
        Assert.IsFalse(sent.Extensions.Any(x => x.Type == 44));
    }

    [TestMethod]
    public async Task Replay_GreaseRegeneratedPerConnection_FirstAndLastExtensionDiffer()
    {
        TlsFingerprint fingerprint = TestFingerprints.Chrome(randomized: false);
        var cipherGreases = new HashSet<ushort>();
        for (int i = 0; i < 6; i++)
        {
            ClientHelloInfo sent = await CaptureAsync(fingerprint, "www.example.com");
            cipherGreases.Add(sent.CipherSuites[0]);

            Assert.IsTrue(GreaseHelper.IsGrease(sent.Extensions[0].Type));
            Assert.IsTrue(GreaseHelper.IsGrease(sent.Extensions[^1].Type));
            Assert.AreNotEqual(sent.Extensions[0].Type, sent.Extensions[^1].Type);
            // group GREASE is shared by supported_groups and key_share
            Assert.AreEqual(sent.SupportedGroups[0], sent.KeyShareGroups[0]);
        }
        Assert.IsGreaterThan(1, cipherGreases.Count);
    }

    [TestMethod]
    public async Task Replay_Randomized_SameExtensionSetGreaseFixedOrderVaries()
    {
        TlsFingerprint fingerprint = TestFingerprints.Chrome(randomized: true);
        var expected = Normalize(fingerprint.Extensions.Select(x => x.Type)).OrderBy(x => x).ToList();
        var orders = new HashSet<string>();
        for (int i = 0; i < 6; i++)
        {
            ClientHelloInfo sent = await CaptureAsync(fingerprint, "www.example.com");
            var types = Normalize(sent.Extensions.Select(x => x.Type));
            CollectionAssert.AreEqual(expected, types.OrderBy(x => x).ToList());
            Assert.AreEqual(GreaseMarker, types[0]);
            Assert.AreEqual(GreaseMarker, types[^1]);
            Assert.AreEqual(fingerprint.Ja4, new Ja4Calculator().Compute(sent));
            orders.Add(string.Join(',', types));
        }
        Assert.IsGreaterThan(1, orders.Count);
    }

    [TestMethod]
    public async Task Replay_PaddingFollowsBoringSslRule()
    {
        TlsFingerprint fingerprint = TestFingerprints.SmallWithPadding();
        Assert.IsTrue(fingerprint.HasPaddingExtension);
        ClientHelloInfo sent = await CaptureAsync(fingerprint, "www.example.com");

        // The unpadded hello falls in BoringSSL's window (256..511 bytes) → padded to exactly 512.
        Assert.IsTrue(sent.Extensions.Any(x => x.Type == 21), $"handshake length {sent.RawHandshake.Length}: padding expected");
        Assert.HasCount(512, sent.RawHandshake);
    }

    [TestMethod]
    public async Task Replay_IpHost_SendsNoSni()
    {
        TlsFingerprint fingerprint = TestFingerprints.Chrome(randomized: false);
        ClientHelloInfo sent = await CaptureAsync(fingerprint, "127.0.0.1");
        Assert.IsNull(sent.ServerName);
        Assert.IsFalse(sent.Extensions.Any(x => x.Type == 0));
    }

    private static async Task<ClientHelloInfo> CaptureAsync(TlsFingerprint fingerprint, string host)
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var server = new ClientHelloCaptureServer();
        Task<ClientHelloInfo> capture = server.CaptureAsync(cts.Token);

        var factory = new FingerprintConnectionFactory(new FingerprintHttpHandlerOptions
        {
            Fingerprint = fingerprint,
            TransportFactory = async (_, _, ct) =>
            {
                var tcp = new TcpClient();
                await tcp.ConnectAsync(System.Net.IPAddress.Loopback, server.Port, ct);
                return tcp.GetStream();
            },
        });
        Task connect = factory.ConnectAsync(host, 443, cts.Token);

        ClientHelloInfo result = await capture;
        try
        {
            await connect;
            Assert.Fail("Handshake against the capture server must fail.");
        }
        catch (Exception ex) when (ex is not AssertFailedException)
        {
            // expected: server closed the connection
        }
        return result;
    }

    private static List<ushort> Normalize(IEnumerable<ushort> values)
        => values.Select(x => GreaseHelper.IsGrease(x) ? GreaseMarker : x).ToList();
}
