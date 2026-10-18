using System.Security.Cryptography;
using System.Text;
using TqkLibrary.TlsFingerCopy.Helpers;
using TqkLibrary.TlsFingerCopy.Models;

namespace TqkLibrary.TlsFingerCopy;

/// <summary>
/// JA3: SSLVersion,Ciphers,Extensions,EllipticCurves,EcPointFormats (decimal, '-' joined, GREASE excluded).
/// </summary>
public class Ja3Calculator
{
    public string BuildString(ClientHelloInfo info)
    {
        string ciphers = Join(info.CipherSuites.Where(x => !GreaseHelper.IsGrease(x)));
        string exts = Join(info.Extensions.Select(x => x.Type).Where(x => !GreaseHelper.IsGrease(x)));
        string curves = Join(info.SupportedGroups.Where(x => !GreaseHelper.IsGrease(x)));
        string formats = Join(info.EcPointFormats.Select(x => (int)x));
        return $"{info.LegacyVersion},{ciphers},{exts},{curves},{formats}";
    }

    public string ComputeHash(string ja3String)
        => Convert.ToHexString(MD5.HashData(Encoding.ASCII.GetBytes(ja3String))).ToLowerInvariant();

    public string ComputeHash(ClientHelloInfo info) => ComputeHash(BuildString(info));

    private static string Join<T>(IEnumerable<T> values) => string.Join('-', values.Select(x => Convert.ToInt32(x)));
}
