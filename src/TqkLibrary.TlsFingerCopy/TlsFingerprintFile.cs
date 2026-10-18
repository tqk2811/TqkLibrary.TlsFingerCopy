using System.Text.Json;
using TqkLibrary.TlsFingerCopy.Models;

namespace TqkLibrary.TlsFingerCopy;

/// <summary>
/// Reads/writes <see cref="TlsFingerprint"/> as indented camelCase JSON.
/// </summary>
public class TlsFingerprintFile
{
    private static readonly JsonSerializerOptions _options = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    public async Task SaveAsync(TlsFingerprint fingerprint, string path, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(fingerprint);
        string? dir = Path.GetDirectoryName(Path.GetFullPath(path));
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
        await using var stream = File.Create(path);
        await JsonSerializer.SerializeAsync(stream, fingerprint, _options, cancellationToken).ConfigureAwait(false);
    }

    public async Task<TlsFingerprint> LoadAsync(string path, CancellationToken cancellationToken = default)
    {
        await using var stream = File.OpenRead(path);
        var result = await JsonSerializer.DeserializeAsync<TlsFingerprint>(stream, _options, cancellationToken).ConfigureAwait(false);
        return result ?? throw new InvalidDataException("Fingerprint file is empty.");
    }
}
