using System.Text.Json.Nodes;
using WsbMcp;

const string Usage = """
    wsb-mcp serve --config <path>   Run the broker (as the user allowed to run wsb.exe).
    wsb-mcp proxy [--pipe <name>]   stdio <-> pipe bridge, launched by the agent's MCP host.
    """;

if (args.Length == 0)
{
    Console.Error.WriteLine(Usage);
    return 2;
}

switch (args[0])
{
    case "serve" when args.Length == 3 && args[1] == "--config":
        return await ServeAsync(args[2]);
    case "proxy" when args.Length == 1:
        return await Proxy.RunAsync("wsb-mcp", 10_000, CancellationToken.None);
    case "proxy" when args.Length == 3 && args[1] == "--pipe":
        return await Proxy.RunAsync(args[2], 10_000, CancellationToken.None);
    default:
        Console.Error.WriteLine(Usage);
        return 2;
}

static async Task<int> ServeAsync(string configPath)
{
    BrokerConfig config;
    try
    {
        config = BrokerConfig.Load(configPath);
    }
    catch (Exception ex) when (ex is InvalidOperationException or IOException or UnauthorizedAccessException)
    {
        Console.Error.WriteLine($"wsb-mcp: {ex.Message}");
        return 1;
    }

    var log = new BrokerLog(config.LogPath, echoToConsole: true);
    var validator = new PathValidator(config.AllowedRoot);
    var sandbox = new SandboxManager(
        new WsbCli(config.WsbPath),
        validator,
        new SandboxOptions(config.StartupTimeout, config.MaxExecTimeoutSeconds, config.IdleTimeout),
        log,
        TimeProvider.System);
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

    log.Write("broker.start", new JsonObject
    {
        ["agentAccount"] = config.AgentAccount,
        ["agentSid"] = config.AgentSid.Value,
        ["allowedRoot"] = validator.Root,
        ["logPath"] = config.LogPath,
    });

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
