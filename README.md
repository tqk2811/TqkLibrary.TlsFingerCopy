# TqkLibrary.TlsFingerCopy

Record the TLS ClientHello of any application into a fingerprint file, then replay that fingerprint when sending HTTP requests from .NET.

## Projects

| Project | Purpose |
|---|---|
| `TqkLibrary.TlsFingerCopy` | ClientHello parser, fingerprint model (JSON), JA3/JA4, sample merging |
| `TqkLibrary.TlsFingerCopy.Recorder` | Local SOCKS5 / HTTP CONNECT / SOCKS4 proxy (built on TqkLibrary.Proxy) that captures ClientHellos without altering traffic |
| `TqkLibrary.TlsFingerCopy.RecorderApp` | Console front-end for the recorder |
| `TqkLibrary.TlsFingerCopy.Http` | `HttpMessageHandler` that performs TLS with a recorded fingerprint (Bouncy Castle fork) under `SocketsHttpHandler` |

## Getting the source

```
git clone --recursive https://github.com/tqk2811/TqkLibrary.TlsFingerCopy.git
```

## Recording

```
TqkLibrary.TlsFingerCopy.RecorderApp --listen 127.0.0.1:1080 --type socks5 --out fingerprints
```

Point the application at the proxy (for example Chrome with `--proxy-server=socks5://127.0.0.1:1080`), or redirect any process to it with a packet redirector such as ProxyDivert. Block UDP 443 so the application falls back from QUIC to TLS over TCP. Press Ctrl+C to stop; one merged JSON file per server name is written into a per-run folder.

## Replaying

```csharp
var fingerprint = await new TlsFingerprintFile().LoadAsync("fingerprints/20261019-120000/www.example.com.json", ct);
using var handler = new FingerprintHttpMessageHandler(new FingerprintHttpHandlerOptions { Fingerprint = fingerprint });
using var client = new HttpClient(handler);
string html = await client.GetStringAsync("https://www.example.com/", ct);
```

Cookies and redirects are disabled inside the handler: put cookie/redirect handlers in front of it (they must see the original `https` URI). Use `TransportFactory` to route the TCP connection through an upstream proxy.

## Limitations

- Only the TLS layer is copied; HTTP/2 SETTINGS and header order still come from .NET.
- QUIC / HTTP/3 is not recorded or replayed.
- See `docs/Backlog-vi.md` for open items.

## Tests

`dotnet test` runs the offline tests. Online tests (tls.peet.ws, google.com) run only with `TLSFINGERCOPY_ONLINE=1`:

```
$env:TLSFINGERCOPY_ONLINE=1; dotnet test --filter "TestCategory=Online"
```

## Third-party

- `libs/bc-csharp`: fork of [Bouncy Castle C#](https://github.com/bcgit/bc-csharp), MIT License (see `libs/bc-csharp/LICENSE.md`). Changes are listed in `libs/bc-csharp/TLSFINGERCOPY_CHANGES.md`.
