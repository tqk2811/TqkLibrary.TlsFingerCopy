using System.Net;
using System.Text.Json;
using TqkLibrary.TlsFingerCopy.Http;
using TqkLibrary.TlsFingerCopy.Models;

namespace TqkLibrary.TlsFingerCopy.Tests.Http;

/// <summary>
/// Needs internet, so gated by an environment variable: a plain <c>dotnet test</c> reports these as inconclusive
/// (skipped). Run them with <c>TLSFINGERCOPY_ONLINE=1</c> set, e.g. PowerShell
/// <c>$env:TLSFINGERCOPY_ONLINE=1; dotnet test --filter "TestCategory=Online"</c>.
/// </summary>
/// <remarks>
/// Not done with a .runsettings TestCaseFilter: VSTest ANDs it with <c>--filter</c>, so the online tests could then
/// never be selected from the command line.
/// </remarks>
[TestClass]
[TestCategory("Online")]
public sealed class OnlineTests
{
    private const string OnlineVariable = "TLSFINGERCOPY_ONLINE";

    [TestInitialize]
    public void RequireOnlineOptIn()
    {
        if (Environment.GetEnvironmentVariable(OnlineVariable) != "1")
            Assert.Inconclusive($"Online test: set {OnlineVariable}=1 to run it.");
    }

    private const string UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";

    [TestMethod]
    public async Task PeetWs_Ja4MatchesFingerprint()
    {
        TlsFingerprint fingerprint = TestFingerprints.Chrome(randomized: true);
        using var client = CreateClient(fingerprint);

        using var response = await client.GetAsync("https://tls.peet.ws/api/all");
        string json = await response.Content.ReadAsStringAsync();
        Assert.AreEqual(HttpStatusCode.OK, response.StatusCode, json);

        using var doc = JsonDocument.Parse(json);
        string? ja4 = doc.RootElement.GetProperty("tls").GetProperty("ja4").GetString();
        Assert.AreEqual(fingerprint.Ja4, ja4);
    }

    [TestMethod]
    public async Task Google_OverHttp2()
    {
        using var client = CreateClient(TestFingerprints.Chrome(randomized: true));

        using var response = await client.GetAsync("https://www.google.com/");
        await response.Content.ReadAsStringAsync();

        Assert.IsTrue(response.IsSuccessStatusCode, response.StatusCode.ToString());
        Assert.AreEqual(HttpVersion.Version20, response.Version);
    }

    private static HttpClient CreateClient(TlsFingerprint fingerprint)
    {
        var handler = new FingerprintHttpMessageHandler(new FingerprintHttpHandlerOptions
        {
            Fingerprint = fingerprint,
            AutomaticDecompression = DecompressionMethods.All,
        });
        var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(30) };
        client.DefaultRequestHeaders.UserAgent.ParseAdd(UserAgent);
        return client;
    }
}
