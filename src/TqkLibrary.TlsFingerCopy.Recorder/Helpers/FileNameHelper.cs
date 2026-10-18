using System.Text;

namespace TqkLibrary.TlsFingerCopy.Recorder.Helpers;

/// <summary>
/// Turns capture keys (host names, IP literals) into safe file names.
/// </summary>
public static class FileNameHelper
{
    private const int MaxLength = 100;

    private static readonly HashSet<string> ReservedNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "con", "prn", "aux", "nul",
        "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8", "com9",
        "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
    };

    /// <summary>
    /// Replaces every character that is not a letter, digit, '.', '-' or '_' with '_', lower-cases the
    /// result and caps its length. Never returns an empty string or a name made only of dots.
    /// Names Windows treats as devices (con, prn, aux, nul, com1-9, lpt1-9, also when followed by an
    /// extension-like suffix such as <c>con.example</c>) get a leading "_".
    /// </summary>
    public static string Sanitize(string key)
    {
        if (string.IsNullOrWhiteSpace(key)) return "unknown";
        var sb = new StringBuilder(Math.Min(key.Length, MaxLength));
        foreach (char c in key.Trim())
        {
            if (sb.Length >= MaxLength) break;
            sb.Append(char.IsAsciiLetterOrDigit(c) || c == '.' || c == '-' || c == '_' ? char.ToLowerInvariant(c) : '_');
        }
        string result = sb.ToString().Trim('.');
        if (result.Length == 0) return "unknown";
        int dot = result.IndexOf('.');
        string stem = dot < 0 ? result : result[..dot];
        return ReservedNames.Contains(stem) ? "_" + result : result;
    }
}
