// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: MIT
// https://github.com/fmuecke/windows-sandbox-mcp
using System.Security.Principal;
using System.Text.Json.Nodes;
using WsbMcp;

const string Usage = """
    wsb-mcp setup --agent <account> --root <dir> [--pipe <name>] [--no-autostart] [--force]
                                      One-time setup as the broker user (not elevated): config, logon task.
    wsb-mcp start | stop              Start the broker task now / stop the broker and its guest.
    wsb-mcp uninstall [--keep-config] Stop, remove the logon task and (unless kept) config and log.
    wsb-mcp diag                      Check the setup; works as the broker user and as the agent.
    wsb-mcp serve [--config <path>]   Run the broker in the foreground (Ctrl+C stops it).
    wsb-mcp proxy [--pipe <name>]     stdio <-> broker bridge, launched by the agent's MCP host.
    wsb-mcp --version
    """;

try
{
    return args switch
    {
        ["--version"] => Print(ToolCatalog.Version),
        ["serve"] => await ServeAsync(BrokerConfig.DefaultConfigPath),
        ["serve", "--config", var path] => await ServeAsync(path),
        ["proxy"] => await Proxy.RunAsync(BrokerConfig.DefaultPipeName, CancellationToken.None),
        ["proxy", "--pipe", var pipe] => await Proxy.RunAsync(pipe, CancellationToken.None),
        ["setup", .. var rest] when ParseSetup(rest) is { } options => await HostCommands.SetupAsync(options, Console.Out),
        ["start"] => await HostCommands.StartAsync(Console.Out),
        ["stop"] => await HostCommands.StopAsync(Console.Out),
        ["uninstall"] => await HostCommands.UninstallAsync(keepConfig: false, Console.Out),
        ["uninstall", "--keep-config"] => await HostCommands.UninstallAsync(keepConfig: true, Console.Out),
        ["diag"] => await HostCommands.DiagAsync(Console.Out),
        _ => UsageError(),
    };
}
catch (Exception ex) when (ex is InvalidOperationException or IOException or UnauthorizedAccessException)
{
    Console.Error.WriteLine($"wsb-mcp: {ex.Message}");
    return 1;
}

static int Print(string text)
{
    Console.WriteLine(text);
    return 0;
}

int UsageError()
{
    Console.Error.WriteLine(Usage);
    return 2;
}

static HostCommands.SetupOptions? ParseSetup(string[] rest)
{
    string? agent = null, root = null, pipe = BrokerConfig.DefaultPipeName;
    bool autostart = true, force = false;
    for (var i = 0; i < rest.Length; i++)
    {
        switch (rest[i])
        {
            case "--agent" when i + 1 < rest.Length:
                agent = rest[++i];
                break;
            case "--root" when i + 1 < rest.Length:
                root = rest[++i];
                break;
            case "--pipe" when i + 1 < rest.Length:
                pipe = rest[++i];
                break;
            case "--no-autostart":
                autostart = false;
                break;
            case "--force":
                force = true;
                break;
            default:
                return null;
        }
    }
    return agent is null || root is null ? null : new HostCommands.SetupOptions(agent, root, pipe, autostart, force);
}

static async Task<int> ServeAsync(string configPath)
{
    var exe = HostCommands.ExecutablePath();
    var problems = SafeLocation.FindProblems(exe, WindowsIdentity.GetCurrent().User!);
    if (problems.Count > 0)
    {
        Console.Error.WriteLine($"wsb-mcp: refusing to serve from '{exe}': other accounts could replace what the broker runs.");
        foreach (var problem in problems)
        {
            Console.Error.WriteLine($"  {problem}");
        }
        return 1;
    }

    var config = BrokerConfig.Load(configPath);
    using var stopSignal = StopSignal.Create(config.PipeName);
    var log = new BrokerLog(config.LogPath, echoToConsole: true);
    var validator = new PathValidator(config.AllowedRoot);
    var sandbox = new SandboxManager(
        new WsbCli(config.WsbPath),
        validator,
        new SandboxOptions(config.StartupTimeout, config.MaxExecTimeoutSeconds, config.IdleTimeout),
        log,
        TimeProvider.System,
        new FileGuestRecord(BrokerConfig.GuestRecordPath));
    var catalog = new ToolCatalog(validator.Root, config.MaxExecTimeoutSeconds, config.IdleTimeout);

    using var shutdown = new CancellationTokenSource();
    Console.CancelKeyPress += (_, e) =>
    {
        e.Cancel = true;
        shutdown.Cancel();
    };
    AppDomain.CurrentDomain.ProcessExit += (_, _) =>
    {
        // Console window closed / logoff: cancel running calls, then stop the guest.
        shutdown.Cancel();
        PipeHost.StopQuietlyAsync(sandbox, "process exit", log).GetAwaiter().GetResult();
    };
    var stopRegistration = ThreadPool.RegisterWaitForSingleObject(
        stopSignal, (_, _) => shutdown.Cancel(), null, Timeout.Infinite, executeOnlyOnce: true);

    log.Write("broker.start", new JsonObject
    {
        ["version"] = ToolCatalog.Version,
        ["executable"] = exe,
        ["agentAccount"] = config.AgentAccount,
        ["agentSid"] = config.AgentSid.Value,
        ["allowedRoot"] = validator.Root,
        ["logPath"] = config.LogPath,
    });

    try
    {
        await sandbox.RecoverAsync(shutdown.Token);
    }
    catch (ToolException ex)
    {
        log.Write("guest.recovery_failed", new JsonObject { ["error"] = ex.Message });
    }

    var idleWatch = WatchIdleAsync(sandbox, shutdown.Token);
    try
    {
        await new PipeHost(config.PipeName, config.AgentSid, sandbox, catalog, log).RunAsync(shutdown.Token);
    }
    catch (OperationCanceledException) when (shutdown.IsCancellationRequested)
    {
    }
    catch (IOException ex)
    {
        log.Write("broker.error", new JsonObject { ["error"] = ex.Message });
        Console.Error.WriteLine($"wsb-mcp: cannot serve pipe '{config.PipeName}' (already in use?): {ex.Message}");
        return 1;
    }
    finally
    {
        stopRegistration.Unregister(null);
        shutdown.Cancel();
        await PipeHost.StopQuietlyAsync(sandbox, "broker shutdown", log);
        await idleWatch;
        log.Write("broker.stop");
    }
    return 0;
}

static async Task WatchIdleAsync(SandboxManager sandbox, CancellationToken cancellationToken)
{
    using var timer = new PeriodicTimer(TimeSpan.FromSeconds(15));
    try
    {
        while (await timer.WaitForNextTickAsync(cancellationToken))
        {
            await sandbox.StopIfIdleAsync();
        }
    }
    catch (OperationCanceledException)
    {
    }
}
