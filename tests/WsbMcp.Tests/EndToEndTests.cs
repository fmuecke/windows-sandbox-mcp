// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: MIT
// https://github.com/fmuecke/windows-sandbox-mcp
using System.Diagnostics;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace WsbMcp.Tests;

/// <summary>
/// Real pipe, real proxy process and real WsbCli against fake-wsb.exe.
/// The "agent" is the current user here; cross-user ACL behaviour was validated by probe (SPEC.md Q1).
/// </summary>
public sealed class EndToEndTests : IDisposable
{
    private readonly WorkDir _work = new();
    private readonly string _root;
    private readonly string _state;
    private readonly string _pipeName = "wsb-mcp-test-" + Guid.NewGuid().ToString("N");
    private readonly CancellationTokenSource _stop = new();
    private Task? _host;
    private SandboxManager? _sandbox;

    public EndToEndTests()
    {
        _root = _work.Dir("root");
        _state = _work.Dir("wsb-state");
    }

    public void Dispose()
    {
        _stop.Cancel();
        try
        {
            _host?.Wait(TimeSpan.FromSeconds(10));
        }
        catch (AggregateException)
        {
        }
        _work.Dispose();
    }

    private static string ToolPath(string name) => Path.Combine(AppContext.BaseDirectory, name);

    private async Task StartHostAsync()
    {
        // WsbCli starts fake-wsb.exe, which reads its state directory from the environment.
        Environment.SetEnvironmentVariable("FAKE_WSB_STATE", _state);
        _sandbox = new SandboxManager(new WsbCli(ToolPath("fake-wsb.exe")), new PathValidator(_root),
            Fixtures.FastOptions, NullBrokerLog.Instance, TimeProvider.System);
        var host = new PipeHost(_pipeName, WindowsIdentity.GetCurrent().User!, _sandbox,
            new ToolCatalog(_root, 600, TimeSpan.FromMinutes(30)), NullBrokerLog.Instance);
        var listening = new TaskCompletionSource();
        host.Listening += () => listening.TrySetResult();
        _host = Task.Run(() => host.RunAsync(_stop.Token));
        await Task.WhenAny(listening.Task, _host);
        if (_host.IsFaulted)
        {
            await _host;
        }
    }

    private static async Task<JsonObject> Rpc(StreamWriter writer, StreamReader reader, string json)
    {
        await writer.WriteLineAsync(json);
        await writer.FlushAsync();
        var line = await reader.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(20))
            ?? throw new AssertFailedException("connection closed");
        return (JsonObject)JsonNode.Parse(line)!;
    }

    private static string CallJson(int id, string tool, JsonObject arguments) =>
        new JsonObject
        {
            ["jsonrpc"] = "2.0",
            ["id"] = id,
            ["method"] = "tools/call",
            ["params"] = new JsonObject { ["name"] = tool, ["arguments"] = arguments },
        }.ToJsonString();

    private string[][] FakeCalls() =>
        File.ReadAllLines(Path.Combine(_state, "calls.jsonl")).Select(l => JsonSerializer.Deserialize<string[]>(l)!).ToArray();

    [Test]
    public async Task ProxyProcessBridgesStdioToBrokerAndArgumentsReachWsbIntact()
    {
        await StartHostAsync();
        var output = _work.Dir(@"root\out dir");
        using var proxy = Process.Start(new ProcessStartInfo(ToolPath("wsb-mcp.exe"))
        {
            ArgumentList = { "proxy", "--pipe", _pipeName },
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            UseShellExecute = false,
        })!;
        var writer = new StreamWriter(proxy.StandardInput.BaseStream, new UTF8Encoding(false)) { NewLine = "\n" };
        var reader = proxy.StandardOutput;

        var init = await Rpc(writer, reader, """{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}""");
        Assert.Equal("2025-06-18", (string?)init["result"]!["protocolVersion"]);

        var start = await Rpc(writer, reader, CallJson(1, "sandbox_start", new JsonObject { ["outputPath"] = output }));
        Assert.Equal(false, (bool?)start["result"]!["isError"], start.ToJsonString());

        // Quotes, spaces, '>' and non-ASCII must arrive as one argv entry.
        const string command = """cmd.exe /c echo "a b" > "C:\SandboxOut\log ü.txt" & exit 0""";
        var exec = await Rpc(writer, reader, CallJson(2, "sandbox_exec", new JsonObject { ["command"] = command }));
        Assert.Equal(0, (int?)exec["result"]!["structuredContent"]!["exitCode"], exec.ToJsonString());

        var failing = await Rpc(writer, reader, CallJson(3, "sandbox_exec", new JsonObject { ["command"] = "cmd.exe /c exit 7" }));
        Assert.Equal(7, (int?)failing["result"]!["structuredContent"]!["exitCode"]);

        var user = await Rpc(writer, reader, CallJson(4, "sandbox_exec", new JsonObject { ["command"] = "whoami", ["runAs"] = "user" }));
        Assert.Equal(0, (int?)user["result"]!["structuredContent"]!["exitCode"], user.ToJsonString());

        var calls = FakeCalls();
        Assert.Equal(SandboxManager.GuestConfiguration, calls.Single(c => c[1] == "start")[3], "config transported intact");
        Assert.True(calls.Any(c => c[1] == "share" && c[5] == output && c[^1] == "-w"), "share with spaces in path");
        Assert.True(calls.Any(c => c[1] == "exec" && c[^1] == command), "command transported intact");
        Assert.True(calls.Any(c => c[1] == "connect"), "lazy connect");

        // Closing the agent side stops the guest.
        proxy.StandardInput.Close();
        Assert.True(proxy.WaitForExit(10_000), "proxy exits");
        await WaitUntil(() => !_sandbox!.IsRunning);
        Assert.True(FakeCalls().Any(c => c[1] == "stop"), "stop on disconnect");
    }

    [Test]
    public async Task ExecTimeoutKillsWsbClientAndReportsTimedOut()
    {
        await StartHostAsync();
        await using var pipe = await ConnectAsync(TokenImpersonationLevel.Identification);
        var (writer, reader) = Wrap(pipe);
        await Rpc(writer, reader, CallJson(1, "sandbox_start", new JsonObject()));
        var watch = Stopwatch.StartNew();
        var exec = await Rpc(writer, reader, CallJson(2, "sandbox_exec", new JsonObject { ["command"] = "sleep 30", ["timeoutSeconds"] = 2 }));
        Assert.Equal(true, (bool?)exec["result"]!["structuredContent"]!["timedOut"], exec.ToJsonString());
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(15), $"returned after timeout ({watch.Elapsed})");
    }

    [Test]
    public async Task RejectsAnonymousClient()
    {
        await StartHostAsync();
        await using var pipe = await ConnectAsync(TokenImpersonationLevel.Anonymous);
        var (writer, reader) = Wrap(pipe);
        try
        {
            await writer.WriteLineAsync("""{"jsonrpc":"2.0","id":1,"method":"ping"}""");
            await writer.FlushAsync();
        }
        catch (IOException)
        {
            // Already disconnected.
        }
        string? line = null;
        try
        {
            line = await reader.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(10));
        }
        catch (IOException)
        {
        }
        Assert.Equal(null, line, "no response to rejected client");

        // The broker keeps serving a proper client afterwards.
        await using var good = await ConnectAsync(TokenImpersonationLevel.Identification);
        var (w2, r2) = Wrap(good);
        Assert.True((await Rpc(w2, r2, """{"jsonrpc":"2.0","id":1,"method":"ping"}"""))["result"] is JsonObject, "ping");
    }

    [Test]
    public async Task PipeNameCannotBeTakenTwiceAndHasRestrictiveAcl()
    {
        await StartHostAsync();
        var second = new PipeHost(_pipeName, WindowsIdentity.GetCurrent().User!, _sandbox!,
            new ToolCatalog(_root, 600, TimeSpan.FromMinutes(30)), NullBrokerLog.Instance);
        var error = await Assert.ThrowsAsync<Exception>(() => second.RunAsync(CancellationToken.None));
        Assert.True(error is IOException or UnauthorizedAccessException, $"unexpected {error.GetType().Name}");

        var agent = new SecurityIdentifier("S-1-5-21-1-2-3-1183");
        var rules = PipeHost.CreateSecurity(agent)
            .GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<PipeAccessRule>().ToList();
        Assert.Equal(3, rules.Count, "ACE count");
        var agentRule = rules.Single(r => r.IdentityReference.Equals(agent));
        Assert.Equal(AccessControlType.Allow, agentRule.AccessControlType);
        Assert.True((agentRule.PipeAccessRights & PipeAccessRights.ReadWrite) == PipeAccessRights.ReadWrite, "agent can read/write");
        const PipeAccessRights forbidden = PipeAccessRights.CreateNewInstance | PipeAccessRights.ChangePermissions |
                                           PipeAccessRights.TakeOwnership | PipeAccessRights.Delete;
        Assert.Equal((PipeAccessRights)0, agentRule.PipeAccessRights & forbidden, "agent rights beyond read/write");
        Assert.True(rules.Any(r => r.AccessControlType == AccessControlType.Deny &&
                                   r.IdentityReference.Equals(new SecurityIdentifier(WellKnownSidType.NetworkSid, null))),
            "network denied");
        Assert.True(!rules.Any(r => r.IsInherited), "no inherited ACEs");
    }

    private async Task<NamedPipeClientStream> ConnectAsync(TokenImpersonationLevel level)
    {
        var pipe = new NamedPipeClientStream(".", _pipeName, PipeDirection.InOut, PipeOptions.Asynchronous, level);
        await pipe.ConnectAsync(10_000);
        return pipe;
    }

    private static (StreamWriter, StreamReader) Wrap(Stream stream) =>
        (new StreamWriter(stream, new UTF8Encoding(false), leaveOpen: true) { NewLine = "\n" },
            new StreamReader(stream, Encoding.UTF8, false, leaveOpen: true));

    private static async Task WaitUntil(Func<bool> condition)
    {
        var watch = Stopwatch.StartNew();
        while (!condition())
        {
            if (watch.Elapsed > TimeSpan.FromSeconds(10))
            {
                throw new AssertFailedException("condition not reached");
            }
            await Task.Delay(50);
        }
    }
}
