using TqkLibrary.TlsFingerCopy.Helpers;
using TqkLibrary.TlsFingerCopy.Models;

namespace TqkLibrary.TlsFingerCopy;

/// <summary>
/// Merges several ClientHello samples of the same client into one fingerprint.
/// </summary>
public class FingerprintMerger
{
    private const ushort GreasePlaceholder = 0x0a0a;
    private const ushort PreSharedKeyType = 41;
    private const ushort EarlyDataType = 42;

    private readonly TlsFingerprintFactory _factory = new();

    public TlsFingerprint Merge(IReadOnlyList<ClientHelloInfo> samples, string? name = null, string? source = null, DateTimeOffset? recordedAt = null)
    {
        ArgumentNullException.ThrowIfNull(samples);
        if (samples.Count == 0) throw new ArgumentException("At least one sample is required.", nameof(samples));

        // Prefer a sample without pre_shared_key as the base (resumption samples carry per-connection data).
        ClientHelloInfo baseSample = samples.FirstOrDefault(x => !HasType(x, PreSharedKeyType)) ?? samples[0];

        bool orderDiffers = false;
        bool grease = false;
        foreach (var sample in samples)
        {
            string? problem = FindIncompatibility(baseSample, sample, out bool sampleOrderDiffers);
            if (problem is not null) throw new ArgumentException(problem, nameof(samples));
            orderDiffers |= sampleOrderDiffers;
            grease |= TlsFingerprintFactory.UsesGrease(sample);
        }

        var fingerprint = _factory.Create(baseSample, name, source, recordedAt);
        fingerprint.SampleCount = samples.Count;
        fingerprint.ExtensionOrderRandomized = orderDiffers;
        fingerprint.UsesGrease = grease;
        return fingerprint;
    }

    /// <summary>
    /// Non-throwing check of whether two samples can be merged together (same extension set ignoring order,
    /// pre_shared_key and early_data, and identical cipher suites, groups, signature algorithms, versions,
    /// ALPN and compression methods; GREASE values are treated as equal). Uses the same rules as <see cref="Merge"/>.
    /// </summary>
    public bool AreCompatible(ClientHelloInfo a, ClientHelloInfo b)
    {
        ArgumentNullException.ThrowIfNull(a);
        ArgumentNullException.ThrowIfNull(b);
        return FindIncompatibility(a, b, out _) is null;
    }

    /// <summary>Single source of the merge rules: null when compatible, otherwise the reason.</summary>
    private static string? FindIncompatibility(ClientHelloInfo baseSample, ClientHelloInfo sample, out bool orderDiffers)
    {
        orderDiffers = false;
        var baseSequence = Normalize(baseSample);
        var sequence = Normalize(sample);
        if (!sequence.OrderBy(x => x).SequenceEqual(baseSequence.OrderBy(x => x)))
            return "Samples have different extension sets.";
        orderDiffers = !sequence.SequenceEqual(baseSequence);

        if (!NormalizeGrease(sample.CipherSuites).SequenceEqual(NormalizeGrease(baseSample.CipherSuites))) return "Samples differ in cipher suites.";
        if (!NormalizeGrease(sample.SupportedGroups).SequenceEqual(NormalizeGrease(baseSample.SupportedGroups))) return "Samples differ in supported groups.";
        if (!sample.SignatureAlgorithms.SequenceEqual(baseSample.SignatureAlgorithms)) return "Samples differ in signature algorithms.";
        if (!NormalizeGrease(sample.SupportedVersions).SequenceEqual(NormalizeGrease(baseSample.SupportedVersions))) return "Samples differ in supported versions.";
        if (!sample.Alpn.SequenceEqual(baseSample.Alpn)) return "Samples differ in ALPN.";
        if (!sample.CompressionMethods.SequenceEqual(baseSample.CompressionMethods)) return "Samples differ in compression methods.";
        return null;
    }

    private static bool HasType(ClientHelloInfo info, ushort type) => info.Extensions.Any(x => x.Type == type);

    private static List<ushort> Normalize(ClientHelloInfo info)
        => info.Extensions
            .Where(x => x.Type != PreSharedKeyType && x.Type != EarlyDataType)
            .Select(x => GreaseHelper.IsGrease(x.Type) ? GreasePlaceholder : x.Type)
            .ToList();

    private static List<ushort> NormalizeGrease(IEnumerable<ushort> values)
        => values.Select(x => GreaseHelper.IsGrease(x) ? GreasePlaceholder : x).ToList();
}
