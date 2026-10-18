namespace TqkLibrary.TlsFingerCopy.Exceptions;

/// <summary>
/// Thrown when TLS data is malformed or cannot be parsed as a ClientHello.
/// </summary>
public class TlsParseException : Exception
{
    public TlsParseException(string message) : base(message)
    {
    }

    public TlsParseException(string message, Exception innerException) : base(message, innerException)
    {
    }
}
