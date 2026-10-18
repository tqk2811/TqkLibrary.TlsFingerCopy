using System.Security.Cryptography;
using System.Text;
using TqkLibrary.TlsFingerCopy.Helpers;
using TqkLibrary.TlsFingerCopy.Models;

namespace TqkLibrary.TlsFingerCopy;

/// <summary>
/// JA4 TLS client fingerprint (FoxIO) in the form a_b_c, protocol 't' (TCP).
/// </summary>
public class Ja4Calculator
{
    private const string EmptyHash = "000000000000";

    public string Compute(ClientHelloInfo info)
    {
        var ciphers = info.CipherSuites.Where(x => !GreaseHelper.IsGrease(x)).ToList();
        var extTypes = info.Extensions.Select(x => x.Type).Where(x => !GreaseHelper.IsGrease(x)).ToList();

        ushort version = info.SupportedVersions.Where(x => !GreaseHelper.IsGrease(x)).DefaultIfEmpty(info.LegacyVersion).Max();
        string sni = info.ServerName is not null || extTypes.Contains(0) ? "d" : "i";
        string a = $"t{VersionCode(version)}{sni}{Math.Min(ciphers.Count, 99):00}{Math.Min(extTypes.Count, 99):00}{AlpnCode(info)}";

        string b = ciphers.Count == 0
            ? EmptyHash
            : Hash(string.Join(',', ciphers.OrderBy(x => x).Select(Hex4)));

        var sortedExts = extTypes.Where(x => x != 0 && x != 16).OrderBy(x => x).Select(Hex4).ToList();
        var sigAlgs = info.SignatureAlgorithms.Where(x => !GreaseHelper.IsGrease(x)).Select(Hex4).ToList();
        string cInput = string.Join(',', sortedExts);
        if (sigAlgs.Count > 0) cInput += "_" + string.Join(',', sigAlgs);
        string c = sortedExts.Count == 0 ? EmptyHash : Hash(cInput);

        return $"{a}_{b}_{c}";
    }

    private static string VersionCode(ushort version) => version switch
    {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        0x0002 => "s2",
        _ => "00",
    };

    private static string AlpnCode(ClientHelloInfo info)
    {
        // Use the raw bytes of the first protocol; the ASCII-decoded string is lossy for non-ASCII bytes.
        byte[] first = info.AlpnRaw.Count > 0
            ? info.AlpnRaw[0]
            : info.Alpn.Count > 0 ? Encoding.Latin1.GetBytes(info.Alpn[0]) : Array.Empty<byte>();
        if (first.Length == 0) return "00";
        byte f = first[0];
        byte l = first[^1];
        if (char.IsAsciiLetterOrDigit((char)f) && char.IsAsciiLetterOrDigit((char)l)) return $"{(char)f}{(char)l}";
        // FoxIO: first char of hex(first byte) and last char of hex(last byte).
        return $"{f:x2}"[0].ToString() + $"{l:x2}"[1];
    }

    private static string Hex4(ushort value) => value.ToString("x4");

    private static string Hash(string input)
        => Convert.ToHexString(SHA256.HashData(Encoding.ASCII.GetBytes(input))).ToLowerInvariant().Substring(0, 12);
}
