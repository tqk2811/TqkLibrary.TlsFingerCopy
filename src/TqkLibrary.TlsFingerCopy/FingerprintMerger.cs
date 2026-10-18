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

        var baseSequence = Normalize(baseSample);
        var baseSorted = baseSequence.OrderBy(x => x).ToList();
        bool orderDiffers = false;
        bool grease = false;
        foreach (var sample in samples)
        {
            var sequence = Normalize(sample);
            if (!sequence.OrderBy(x => x).SequenceEqual(baseSorted))
                throw new ArgumentException("Samples have different extension sets.", nameof(samples));
            if (!sequence.SequenceEqual(baseSequence)) orderDiffers = true;
            grease |= TlsFingerprintFactory.UsesGrease(sample);

            CheckEqual("cipher suites", NormalizeGrease(sample.CipherSuites), NormalizeGrease(baseSample.CipherSuites));
            CheckEqual("supported groups", NormalizeGrease(sample.SupportedGroups), NormalizeGrease(baseSample.SupportedGroups));
            CheckEqual("signature algorithms", sample.SignatureAlgorithms, baseSample.SignatureAlgorithms);
            CheckEqual("supported versions", NormalizeGrease(sample.SupportedVersions), NormalizeGrease(baseSample.SupportedVersions));
            CheckEqual("ALPN", sample.Alpn, baseSample.Alpn);
            CheckEqual("compression methods", sample.CompressionMethods, baseSample.CompressionMethods);
        }

        var fingerprint = _factory.Create(baseSample, name, source, recordedAt);
        fingerprint.SampleCount = samples.Count;
        fingerprint.ExtensionOrderRandomized = orderDiffers;
        fingerprint.UsesGrease = grease;
        return fingerprint;
    }

    private static bool HasType(ClientHelloInfo info, ushort type) => info.Extensions.Any(x => x.Type == type);

    private static List<ushort> Normalize(ClientHelloInfo info)
        => info.Extensions
            .Where(x => x.Type != PreSharedKeyType && x.Type != EarlyDataType)
            .Select(x => GreaseHelper.IsGrease(x.Type) ? GreasePlaceholder : x.Type)
            .ToList();

    private static List<ushort> NormalizeGrease(IEnumerable<ushort> values)
        => values.Select(x => GreaseHelper.IsGrease(x) ? GreasePlaceholder : x).ToList();

    private static void CheckEqual<T>(string field, IEnumerable<T> actual, IEnumerable<T> expected)
    {
        if (!actual.SequenceEqual(expected))
            throw new ArgumentException($"Samples differ in {field}.", "samples");
    }
}
