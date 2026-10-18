using TqkLibrary.TlsFingerCopy.Models;
using TqkLibrary.TlsFingerCopy.Recorder.Helpers;

namespace TqkLibrary.TlsFingerCopy.Recorder.Models;

/// <summary>
/// Thread-safe store of captured ClientHello samples, grouped by key (<c>ServerName ?? target host</c>).
/// </summary>
public class CaptureSession
{
    private readonly object _lock = new();
    private readonly Dictionary<string, List<ClientHelloInfo>> _groups = new(StringComparer.OrdinalIgnoreCase);
    private readonly FingerprintMerger _merger = new();
    private readonly TlsFingerprintFile _file = new();

    /// <summary>Total number of samples stored.</summary>
    public int SampleCount
    {
        get { lock (_lock) return _groups.Values.Sum(x => x.Count); }
    }

    /// <summary>Adds a sample and returns the key it was grouped under.</summary>
    public string Add(ClientHelloInfo info, string targetHost)
    {
        ArgumentNullException.ThrowIfNull(info);
        string key = GetKey(info, targetHost);
        lock (_lock)
        {
            if (!_groups.TryGetValue(key, out List<ClientHelloInfo>? list))
            {
                list = new List<ClientHelloInfo>();
                _groups[key] = list;
            }
            list.Add(info);
        }
        return key;
    }

    /// <summary>Key a sample is stored under: the SNI when present, otherwise the target host.</summary>
    public static string GetKey(ClientHelloInfo info, string targetHost)
        => string.IsNullOrEmpty(info.ServerName) ? targetHost : info.ServerName;

    /// <summary>Snapshot of the samples per key.</summary>
    public IReadOnlyDictionary<string, IReadOnlyList<ClientHelloInfo>> GetGroups()
    {
        lock (_lock)
        {
            return _groups.ToDictionary(x => x.Key, x => (IReadOnlyList<ClientHelloInfo>)x.Value.ToArray(), StringComparer.OrdinalIgnoreCase);
        }
    }

    /// <summary>
    /// Writes one merged fingerprint file per group to <paramref name="outputDirectory"/> as
    /// <c>&lt;sanitized-key&gt;.json</c>. When the samples of a group cannot be merged (different
    /// extension sets) they are split into compatible buckets saved as <c>&lt;key&gt;-1.json</c>,
    /// <c>&lt;key&gt;-2.json</c>, ... Returns the written file paths.
    /// </summary>
    public async Task<IReadOnlyList<string>> SaveAsync(string outputDirectory, string? source = null, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(outputDirectory);
        var groups = GetGroups();
        Directory.CreateDirectory(outputDirectory);

        var written = new List<string>();
        var usedNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var group in groups.OrderBy(x => x.Key, StringComparer.OrdinalIgnoreCase))
        {
            List<List<ClientHelloInfo>> buckets = Partition(group.Value);
            string baseName = FileNameHelper.Sanitize(group.Key);
            for (int i = 0; i < buckets.Count; i++)
            {
                string name = buckets.Count == 1 ? baseName : $"{baseName}-{i + 1}";
                string unique = name;
                for (int n = 2; !usedNames.Add(unique); n++) unique = $"{name}~{n}";

                TlsFingerprint fingerprint = _merger.Merge(buckets[i], group.Key, source);
                string path = Path.Combine(outputDirectory, unique + ".json");
                await _file.SaveAsync(fingerprint, path, cancellationToken).ConfigureAwait(false);
                written.Add(path);
            }
        }
        return written;
    }

    /// <summary>Greedy split: a sample joins the first bucket whose first sample it is compatible with.</summary>
    private List<List<ClientHelloInfo>> Partition(IReadOnlyList<ClientHelloInfo> samples)
    {
        var buckets = new List<List<ClientHelloInfo>>();
        foreach (ClientHelloInfo sample in samples)
        {
            List<ClientHelloInfo>? bucket = buckets.Find(x => _merger.AreCompatible(x[0], sample));
            if (bucket is null) buckets.Add(new List<ClientHelloInfo> { sample });
            else bucket.Add(sample);
        }
        return buckets;
    }
}
