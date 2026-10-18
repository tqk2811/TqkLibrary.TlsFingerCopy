using System.Net;
using TqkLibrary.TlsFingerCopy;
using TqkLibrary.TlsFingerCopy.Recorder;
using TqkLibrary.TlsFingerCopy.Recorder.Enums;
using TqkLibrary.TlsFingerCopy.Recorder.Models;

namespace TqkLibrary.TlsFingerCopy.RecorderApp;

internal static class Program
{
    private const string Help = """
        TqkLibrary.TlsFingerCopy.RecorderApp - records TLS ClientHello fingerprints through a local proxy.

        Usage:
          RecorderApp --listen 127.0.0.1:1080 --type socks5 --out <dir> [--source <label>]

          --listen  local endpoint to listen on (default 127.0.0.1:1080)
          --type    socks5 | http | socks4 (default socks5)
          --out     base output directory (required); each run writes <host>.json files into its own
                    <out>/yyyyMMdd-HHmmss subfolder
          --source  free-text label stored in the fingerprint (e.g. the app name)

        Point the target application at the proxy, or redirect it with ProxyDivert (WinDivert); in
        that case the CONNECT target is often an IP and the host name is taken from the SNI.
        QUIC/HTTP3 is not recorded: block outgoing UDP 443 so the application falls back to TCP TLS.
        Press Ctrl+C once to stop and save; press it a second time to exit immediately.
        """;

    private static async Task<int> Main(string[] args)
    {
        if (args.Length == 0 || args.Contains("--help") || args.Contains("-h") || args.Contains("/?"))
        {
            Console.WriteLine(Help);
            return args.Length == 0 ? 1 : 0;
        }

        string listen = "127.0.0.1:1080";
        string type = "socks5";
        string? outDir = null;
        string? source = null;
        for (int i = 0; i < args.Length; i++)
        {
            string? value = i + 1 < args.Length ? args[i + 1] : null;
            switch (args[i])
            {
                case "--listen": listen = value ?? ""; i++; break;
                case "--type": type = value ?? ""; i++; break;
                case "--out": outDir = value; i++; break;
                case "--source": source = value; i++; break;
                default:
                    Console.Error.WriteLine($"Unknown argument: {args[i]}");
                    return 2;
            }
        }

        if (string.IsNullOrEmpty(outDir))
        {
            Console.Error.WriteLine("--out is required.");
            return 2;
        }
        if (!IPEndPoint.TryParse(listen, out IPEndPoint? endPoint))
        {
            Console.Error.WriteLine($"Invalid --listen value: {listen}");
            return 2;
        }
        if (!Enum.TryParse(type, true, out RecorderProxyType proxyType) || !Enum.IsDefined(proxyType))
        {
            Console.Error.WriteLine($"Invalid --type value: {type}");
            return 2;
        }

        var options = new RecorderOptions
        {
            ListenEndPoint = endPoint,
            ProxyType = proxyType,
            OutputDirectory = outDir,
            Source = source,
        };

        await using var recorder = new FingerprintRecorder(options);
        var ja3 = new Ja3Calculator();
        var ja4 = new Ja4Calculator();
        var consoleLock = new object();
        recorder.ClientHelloCaptured += (_, e) =>
        {
            lock (consoleLock)
            {
                Console.WriteLine($"{e.CapturedAt.LocalDateTime:HH:mm:ss} {e.TargetHost}:{e.TargetPort} sni={e.ServerName ?? "-"} ja4={ja4.Compute(e.ClientHello)} ja3={ja3.ComputeHash(e.ClientHello)}");
            }
        };

        using var stop = new CancellationTokenSource();
        int pressCount = 0;
        // Single stop path shared by the normal exit and ProcessExit: first caller runs it, others await the same task.
        var stopTask = new Lazy<Task<IReadOnlyList<string>>>(() => recorder.StopAsync());

        ConsoleCancelEventHandler onCancel = (_, e) =>
        {
            if (Interlocked.Increment(ref pressCount) > 1) return; // second press: let the runtime exit now
            e.Cancel = true;
            try { stop.Cancel(); }
            catch (ObjectDisposedException) { }
        };
        EventHandler onProcessExit = (_, _) =>
        {
            try { stopTask.Value.Wait(TimeSpan.FromSeconds(5)); }
            catch { }
        };
        Console.CancelKeyPress += onCancel;
        AppDomain.CurrentDomain.ProcessExit += onProcessExit;

        try
        {
            try
            {
                recorder.Start();
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Cannot start: {ex.Message}");
                return 1;
            }
            Console.WriteLine($"Listening on {recorder.LocalEndPoint} ({proxyType}). Ctrl+C to stop and save.");

            try { await Task.Delay(Timeout.Infinite, stop.Token); }
            catch (OperationCanceledException) { }

            try
            {
                IReadOnlyList<string> files = await stopTask.Value;
                Console.WriteLine(files.Count == 0 ? "Nothing captured." : $"Saved to {recorder.RunDirectory}:");
                foreach (string file in files) Console.WriteLine("  " + file);
                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Failed to stop/save: {ex.Message}");
                return 1;
            }
        }
        finally
        {
            Console.CancelKeyPress -= onCancel;
            AppDomain.CurrentDomain.ProcessExit -= onProcessExit;
        }
    }
}
