using System.Text.Json.Nodes;

namespace WsbMcp.Tests;

public sealed class SandboxManagerTests : IDisposable
{
    private readonly WorkDir _work = new();
    private readonly string _root;
    private readonly ScriptedWsb _wsb = new();
    private readonly SelfClient _client = new();
    private readonly CancellationToken _ct = CancellationToken.None;

    public SandboxManagerTests()
    {
        _root = _work.Dir("root");
    }

    public void Dispose() => _work.Dispose();

    private SandboxManager Manager(TimeProvider? time = null) => Fixtures.Manager(_wsb, _root, time);

    [Test]
    public async Task StartPassesHardcodedConfigAndSharesReadOnlyInputAndWritableOutput()
    {
        var input = _work.Dir(@"root\in");
        var output = _work.Dir(@"root\out");
        var result = await Manager().StartAsync(input, output, _client, _ct);

        Assert.Equal("id-1", (string?)result["id"]);
        Assert.Equal(SandboxManager.InputGuestPath, (string?)result["inputGuestPath"]);
        Assert.Equal(SandboxManager.OutputGuestPath, (string?)result["outputGuestPath"]);

        var start = _wsb.CallsOf("start").Single();
        Assert.Equal(SandboxManager.GuestConfiguration, start[2], "config");
        Assert.Contains("<Networking>Disable</Networking>", start[2]);

        var shares = _wsb.CallsOf("share").ToList();
        Assert.Equal(string.Join(' ', "share", "--id", "id-1", "-f", input, "-s", @"C:\SandboxIn"), string.Join(' ', shares[0]));
        Assert.Equal(string.Join(' ', "share", "--id", "id-1", "-f", output, "-s", @"C:\SandboxOut", "-w"), string.Join(' ', shares[1]));
    }

    [Test]
    public async Task SameInputAndOutputIsSharedOnceWritable()
    {
        var dir = _work.Dir(@"root\both");
        var result = await Manager().StartAsync(dir, dir.ToUpperInvariant(), _client, _ct);
        Assert.Equal(null, result["inputGuestPath"]);
        Assert.Equal(SandboxManager.OutputGuestPath, (string?)result["outputGuestPath"]);
        var share = _wsb.CallsOf("share").Single();
        Assert.Equal("-w", share[^1]);
    }

    [Test]
    public async Task StartRefusesWhenAnotherSandboxRunsAndValidatesBeforeStarting()
    {
        _wsb.OtherSandboxRunning = true;
        var error = await Assert.ThrowsAsync<ToolException>(() => Manager().StartAsync(null, null, _client, _ct));
        Assert.Contains("already running", error.Message);

        _wsb.OtherSandboxRunning = false;
        await Assert.ThrowsAsync<ToolException>(() => Manager().StartAsync(@"C:\Windows", null, _client, _ct));
        Assert.Equal(0, _wsb.CallsOf("start").Count(), "start calls");
    }

    [Test]
    public async Task StartRetriesShareUntilGuestIsReady()
    {
        _wsb.ShareFailuresBeforeReady = 3;
        await Manager().StartAsync(null, _work.Dir(@"root\out"), _client, _ct);
        Assert.Equal(4, _wsb.CallsOf("share").Count(), "share attempts");
    }

    [Test]
    public async Task StartStopsGuestWhenShareNeverSucceeds()
    {
        _wsb.ShareAlwaysFails = true;
        var manager = Manager();
        var error = await Assert.ThrowsAsync<ToolException>(() => manager.StartAsync(null, _work.Dir(@"root\out"), _client, _ct));
        Assert.Contains("did not accept the share", error.Message);
        Assert.Equal(1, _wsb.CallsOf("stop").Count(), "stop calls");
        Assert.True(!manager.IsRunning, "manager must not own a guest");
        Assert.True(!_wsb.Running, "guest stopped");
    }

    [Test]
    public async Task StartWithoutMappingsWaitsForGuestReadiness()
    {
        var attempts = 0;
        _wsb.Exec = _ => ++attempts < 3 ? new WsbResult(1, "not ready", false) : ScriptedWsb.Ok("""{"ExitCode": 0}""");
        await Manager().StartAsync(null, null, _client, _ct);
        Assert.Equal(3, attempts, "readiness probes");
    }

    [Test]
    public async Task StartTwiceRequiresStop()
    {
        var manager = Manager();
        await manager.StartAsync(null, null, _client, _ct);
        Assert.Contains("sandbox_stop", (await Assert.ThrowsAsync<ToolException>(() => manager.StartAsync(null, null, _client, _ct))).Message);
    }

    [Test]
    public async Task ExecReportsGuestExitCodeFromJsonNotWsbExitCode()
    {
        var manager = Manager();
        await manager.StartAsync(null, _work.Dir(@"root\out"), _client, _ct);
        _wsb.Exec = _ => ScriptedWsb.Ok("""{"ExitCode": 7}""");
        var result = await manager.ExecAsync("cmd.exe /c exit 7", null, RunAs.System, null, _ct);
        Assert.Equal(7, (int?)result["exitCode"]);
        Assert.Equal(false, (bool?)result["timedOut"]);

        _wsb.Exec = _ => ScriptedWsb.Ok("""{"ExitCode": 3221225477}""");
        result = await manager.ExecAsync("crash.exe", null, RunAs.System, null, _ct);
        Assert.Equal(unchecked((int)0xC0000005), (int?)result["exitCode"]);

        var exec = _wsb.CallsOf("exec").Last();
        Assert.Equal(string.Join('|', "exec", "--id", "id-1", "-d", @"C:\SandboxOut", "-r", "System", "-c", "crash.exe"),
            string.Join('|', exec));
    }

    [Test]
    public async Task ExecLaunchFailureAndMissingExitCodeAreErrors()
    {
        var manager = Manager();
        await manager.StartAsync(null, null, _client, _ct);
        _wsb.Exec = _ => new WsbResult(unchecked((int)0x80070002), "file not found", false);
        Assert.Contains("could not launch",
            (await Assert.ThrowsAsync<ToolException>(() => manager.ExecAsync("x.exe", null, RunAs.System, null, _ct))).Message);
        _wsb.Exec = _ => ScriptedWsb.Ok("{}");
        Assert.Contains("did not report a guest exit code",
            (await Assert.ThrowsAsync<ToolException>(() => manager.ExecAsync("x.exe", null, RunAs.System, null, _ct))).Message);
    }

    [Test]
    public async Task ExecAsUserConnectsLazilyAndRetries()
    {
        var manager = Manager();
        await manager.StartAsync(null, null, _client, _ct);
        var result = await manager.ExecAsync("whoami", @"C:\", RunAs.User, null, _ct);
        Assert.Equal(0, (int?)result["exitCode"]);
        Assert.Equal("connect|--id|id-1", string.Join('|', _wsb.Launches.Single()));
        Assert.Equal("ExistingLogin", _wsb.CallsOf("exec").Last()[6]);

        // Session exists now: no further connect.
        await manager.ExecAsync("whoami", null, RunAs.User, null, _ct);
        Assert.Equal(1, _wsb.Launches.Count, "connect launches");
    }

    [Test]
    public async Task ExecAsUserFailsWhenSessionNeverAppears()
    {
        var manager = Manager();
        await manager.StartAsync(null, null, _client, _ct);
        _wsb.Exec = _ => new WsbResult(SandboxManager.NoLogonSession, "no session", false);
        Assert.Contains("No user session",
            (await Assert.ThrowsAsync<ToolException>(() => manager.ExecAsync("whoami", null, RunAs.User, null, _ct))).Message);
    }

    [Test]
    public async Task ExecTimeoutIsReportedNotThrown()
    {
        var manager = Manager();
        await manager.StartAsync(null, null, _client, _ct);
        _wsb.Exec = _ => new WsbResult(-1, "", true);
        var result = await manager.ExecAsync("hang.exe", null, RunAs.System, 5, _ct);
        Assert.Equal(true, (bool?)result["timedOut"]);
        Assert.Equal(null, result["exitCode"]);
        Assert.True(manager.IsRunning, "guest keeps running");
    }

    [Test]
    public async Task ExecRejectsArgumentsWsbWouldMisparse()
    {
        var manager = Manager();
        await manager.StartAsync(null, null, _client, _ct);
        foreach (var command in new[] { "@C:\\Users\\secret.rsp", "--id other", "-c x", "", "  ", "a\0b", new string('x', 8001) })
        {
            await Assert.ThrowsAsync<ToolException>(() => manager.ExecAsync(command, null, RunAs.System, null, _ct));
        }
        await Assert.ThrowsAsync<ToolException>(() => manager.ExecAsync("ok", "@C:\\x", RunAs.System, null, _ct));
        await Assert.ThrowsAsync<ToolException>(() => manager.ExecAsync("ok", null, RunAs.System, 0, _ct));
        await Assert.ThrowsAsync<ToolException>(() => manager.ExecAsync("ok", null, RunAs.System, 601, _ct));
        Assert.Equal(1, _wsb.CallsOf("exec").Count(), "only the readiness probe ran");
    }

    [Test]
    public async Task ExecWithoutGuestFails()
    {
        Assert.Contains("sandbox_start",
            (await Assert.ThrowsAsync<ToolException>(() => Manager().ExecAsync("x", null, RunAs.System, null, _ct))).Message);
    }

    [Test]
    public async Task StopIsIdempotent()
    {
        var manager = Manager();
        Assert.Equal(false, (bool?)(await manager.StopAsync("t", _ct))["stopped"]);
        await manager.StartAsync(null, null, _client, _ct);
        Assert.Equal(true, (bool?)(await manager.StopAsync("t", _ct))["stopped"]);
        Assert.Equal(false, (bool?)(await manager.StopAsync("t", _ct))["stopped"]);
        Assert.True(!_wsb.Running, "guest stopped");
    }

    [Test]
    public async Task StatusReportsMappingsAndDetectsVanishedGuest()
    {
        var manager = Manager();
        var output = _work.Dir(@"root\out");
        await manager.StartAsync(null, output, _client, _ct);
        var status = await manager.StatusAsync(_ct);
        Assert.Equal(true, (bool?)status["running"]);
        Assert.Equal(output, (string?)status["outputHostPath"]);

        _wsb.Running = false; // Closed outside the broker.
        status = await manager.StatusAsync(_ct);
        Assert.Equal(false, (bool?)status["running"]);
        Assert.Contains("no longer running", (string?)status["note"]);
    }

    [Test]
    public async Task IdleTimeoutStopsGuestOnlyAfterInactivity()
    {
        var time = new ManualTime();
        var manager = Manager(time);
        await manager.StartAsync(null, null, _client, _ct);

        time.Advance(TimeSpan.FromMinutes(29));
        await manager.StopIfIdleAsync();
        Assert.True(manager.IsRunning, "still running before timeout");

        await manager.StatusAsync(_ct); // Activity resets the clock.
        time.Advance(TimeSpan.FromMinutes(29));
        await manager.StopIfIdleAsync();
        Assert.True(manager.IsRunning, "activity extends lifetime");

        time.Advance(TimeSpan.FromMinutes(1));
        await manager.StopIfIdleAsync();
        Assert.True(!manager.IsRunning, "stopped after idle timeout");
    }

    [Test]
    public async Task IdleCheckSkipsWhileACallIsInProgress()
    {
        var time = new ManualTime();
        var manager = Manager(time);
        await manager.StartAsync(null, null, _client, _ct);
        var release = new TaskCompletionSource();
        var entered = new TaskCompletionSource();
        _wsb.Exec = _ =>
        {
            entered.SetResult();
            release.Task.Wait();
            return ScriptedWsb.Ok("""{"ExitCode": 0}""");
        };
        var exec = Task.Run(() => manager.ExecAsync("long.exe", null, RunAs.System, null, _ct));
        await entered.Task;
        time.Advance(TimeSpan.FromHours(2));
        await manager.StopIfIdleAsync();
        Assert.True(manager.IsRunning, "not stopped during a call");
        release.SetResult();
        await exec;
    }

    [Test]
    public void GuestConfigurationIsTheHardenedOne()
    {
        var config = System.Xml.Linq.XElement.Parse(SandboxManager.GuestConfiguration);
        var settings = config.Elements().ToDictionary(e => e.Name.LocalName, e => e.Value);
        Assert.Equal("Disable", settings["Networking"]);
        Assert.Equal("Disable", settings["vGPU"]);
        Assert.Equal("Disable", settings["ClipboardRedirection"]);
        Assert.Equal("Disable", settings["AudioInput"]);
        Assert.Equal("Disable", settings["VideoInput"]);
        Assert.Equal("Disable", settings["PrinterRedirection"]);
        Assert.Equal("Enable", settings["ProtectedClient"]);
        Assert.Equal(7, settings.Count, "no other settings (no mapped folders, no logon command)");
    }
}
