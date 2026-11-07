// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: MIT
// https://github.com/fmuecke/windows-sandbox-mcp
using System.IO.Pipes;
using System.Security.Principal;
using System.Text;
using System.Text.Json.Nodes;

namespace WsbMcp.Tests;

/// <summary>The proxy without a broker (hint), reconnecting to a late broker, and losing it.</summary>
public sealed class ProxyTests : IDisposable
{
    private readonly WorkDir _work = new();
    private readonly string _pipeName = "wsb-mcp-test-" + Guid.NewGuid().ToString("N");
    private readonly AnonymousPipeServerStream _toProxy = new(PipeDirection.Out);
    private readonly AnonymousPipeServerStream _fromProxy = new(PipeDirection.In);
    private readonly StreamWriter _writer;
    private readonly StreamReader _reader;
    private readonly Task<int> _proxy;
    private CancellationTokenSource? _hostStop;
    private Task? _host;

    public ProxyTests()
    {
        var proxyIn = new AnonymousPipeClientStream(PipeDirection.In, _toProxy.ClientSafePipeHandle);
        var proxyOut = new AnonymousPipeClientStream(PipeDirection.Out, _fromProxy.ClientSafePipeHandle);
        _writer = new StreamWriter(_toProxy, new UTF8Encoding(false)) { NewLine = "\n", AutoFlush = true };
        _reader = new StreamReader(_fromProxy, Encoding.UTF8);
        _proxy = Task.Run(() => new Proxy(_pipeName, proxyIn, proxyOut, TimeSpan.FromMilliseconds(300)).RunAsync(CancellationToken.None));
    }

    public void Dispose()
    {
        _writer.Dispose();
        _hostStop?.Cancel();
        try
        {
            _proxy.Wait(TimeSpan.FromSeconds(10));
            _host?.Wait(TimeSpan.FromSeconds(10));
        }
        catch (AggregateException)
        {
        }
        _work.Dispose();
    }

    private async Task<JsonObject> Rpc(string json)
    {
        await _writer.WriteLineAsync(json);
        var line = await _reader.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(20))
            ?? throw new AssertFailedException("proxy closed");
        return (JsonObject)JsonNode.Parse(line)!;
    }

    private Task<JsonObject> Call(int id, string tool) =>
        Rpc(new JsonObject
        {
            ["jsonrpc"] = "2.0",
            ["id"] = id,
            ["method"] = "tools/call",
            ["params"] = new JsonObject { ["name"] = tool, ["arguments"] = new JsonObject() },
        }.ToJsonString());

    private async Task Handshake()
    {
        var init = await Rpc("""{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}""");
        Assert.Equal("wsb-mcp", (string?)init["result"]!["serverInfo"]!["name"]);
        await _writer.WriteLineAsync("""{"jsonrpc":"2.0","method":"notifications/initialized"}""");
    }

    private async Task StartBrokerAsync()
    {
        var root = _work.Dir("root");
        Environment.SetEnvironmentVariable("FAKE_WSB_STATE", _work.Dir("wsb-state"));
        var sandbox = new SandboxManager(new WsbCli(Path.Combine(AppContext.BaseDirectory, "fake-wsb.exe")),
            new PathValidator(root), Fixtures.FastOptions, NullBrokerLog.Instance, TimeProvider.System);
        var host = new PipeHost(_pipeName, WindowsIdentity.GetCurrent().User!, sandbox,
            new ToolCatalog(root, 600, TimeSpan.FromMinutes(30)), NullBrokerLog.Instance);
        var listening = new TaskCompletionSource();
        host.Listening += () => listening.TrySetResult();
        _hostStop = new CancellationTokenSource();
        _host = Task.Run(() => host.RunAsync(_hostStop.Token));
        await Task.WhenAny(listening.Task, _host);
    }

    [Test]
    public async Task WithoutBrokerToolsAreListedAndCallsReturnTheHint()
    {
        await Handshake();
        var tools = await Rpc("""{"jsonrpc":"2.0","id":1,"method":"tools/list"}""");
        Assert.Equal("sandbox_start,sandbox_exec,sandbox_status,sandbox_stop",
            string.Join(',', tools["result"]!["tools"]!.AsArray().Select(t => (string?)t!["name"])));
        Assert.True((await Rpc("""{"jsonrpc":"2.0","id":2,"method":"ping"}"""))["result"] is JsonObject, "ping");

        var call = await Call(3, "sandbox_status");
        Assert.Equal(true, (bool?)call["result"]!["isError"]);
        Assert.Contains("wsb-mcp start", (string?)call["result"]!["content"]![0]!["text"]);
    }

    [Test]
    public async Task ReconnectsWhenTheBrokerAppearsLater()
    {
        await Handshake();
        Assert.Equal(true, (bool?)(await Call(1, "sandbox_status"))["result"]!["isError"], "offline first");

        await StartBrokerAsync();
        var status = await Call(2, "sandbox_status");
        Assert.Equal(false, (bool?)status["result"]!["isError"], status.ToJsonString());
        Assert.Equal(false, (bool?)status["result"]!["structuredContent"]!["running"]);
        Assert.Equal(2, (int?)status["id"], "the client's id, not the replay id");
    }

    [Test]
    public async Task FallsBackToTheHintWhenTheBrokerGoesAway()
    {
        await StartBrokerAsync();
        await Handshake();
        Assert.Equal(false, (bool?)(await Call(1, "sandbox_status"))["result"]!["isError"], "online");

        _hostStop!.Cancel();
        await _host!.WaitAsync(TimeSpan.FromSeconds(10)).ContinueWith(_ => { });
        // The proxy notices the closed pipe; calls then return the hint instead of hanging.
        var deadline = DateTime.UtcNow.AddSeconds(10);
        JsonObject call;
        do
        {
            call = await Call(2, "sandbox_status");
        }
        while ((bool?)call["result"]?["isError"] != true && DateTime.UtcNow < deadline);
        Assert.Contains("not reachable", (string?)call["result"]!["content"]![0]!["text"]);
    }

    [Test]
    public async Task PendingResponseIsDeliveredAfterTheClientClosesInput()
    {
        await StartBrokerAsync();
        await Handshake();
        await _writer.WriteLineAsync("""{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"sandbox_status","arguments":{}}}""");
        _writer.Close(); // EOF right after the request, like 'echo ... | wsb-mcp proxy'.
        var line = await _reader.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(20));
        Assert.Equal(7, (int?)JsonNode.Parse(line!)!["id"], line);
        Assert.Equal(0, await _proxy.WaitAsync(TimeSpan.FromSeconds(10)), "proxy exit code");
    }
}
