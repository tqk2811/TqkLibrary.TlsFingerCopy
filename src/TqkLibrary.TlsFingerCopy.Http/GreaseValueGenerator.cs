using System.Security.Cryptography;

namespace TqkLibrary.TlsFingerCopy.Http;

/// <summary>
/// Picks the GREASE values (RFC 8701) of one connection, the way BoringSSL does: one random value per role
/// (cipher suite, group, version, signature algorithm), and distinct values for successive GREASE extensions.
/// </summary>
internal class GreaseValueGenerator
{
    private readonly List<ushort> _extensionValues = new();

    public GreaseValueGenerator()
    {
        CipherSuite = Next();
        Group = Next();
        Version = Next();
        SignatureAlgorithm = Next();
    }

    public ushort CipherSuite { get; }

    public ushort Group { get; }

    public ushort Version { get; }

    public ushort SignatureAlgorithm { get; }

    /// <summary>
    /// Value for the n-th GREASE extension of the ClientHello; every call returns a value not used by a previous
    /// extension of this connection (BoringSSL: the first and last GREASE extensions differ).
    /// </summary>
    public ushort NextExtension()
    {
        ushort value = Next();
        if (_extensionValues.Count < 16)
        {
            while (_extensionValues.Contains(value)) value = Next();
        }
        _extensionValues.Add(value);
        return value;
    }

    /// <summary>Random value of the form 0x?A?A.</summary>
    public static ushort Next()
    {
        int nibble = RandomNumberGenerator.GetInt32(16);
        byte b = (byte)((nibble << 4) | 0x0a);
        return (ushort)((b << 8) | b);
    }
}
