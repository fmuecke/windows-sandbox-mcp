// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: MIT
// https://github.com/fmuecke/windows-sandbox-mcp
using System.ComponentModel;
using System.Diagnostics;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json.Nodes;
using System.Xml.Linq;

namespace WsbMcp;

/// <summary>setup / start / stop / uninstall / diag (SPEC.md "Setup and distribution").</summary>
public static class HostCommands
{
    public const string TaskName = @"\wsb-mcp broker";

    private const string EnableSandboxCommand =
        "Enable-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM -All   (as admin, then reboot)";

    public sealed record SetupOptions(string Agent, string Root, string PipeName, bool Autostart, bool Force);

    public static async Task<int> SetupAsync(SetupOptions options, TextWriter output)
    {
        if (IsElevated())
        {
            output.WriteLine("FAIL Run 'wsb-mcp setup' from a normal (not elevated) terminal: the broker, its task " +
                             "and its config must belong to your own account.");
            return 1;
        }
        var self = WindowsIdentity.GetCurrent().User!;
        var exe = ExecutablePath();

        var problems = SafeLocation.FindProblems(exe, self);
        if (problems.Count > 0)
        {
            output.WriteLine($"FAIL '{exe}' is not in a safe location; other accounts could replace what the broker runs:");
            foreach (var problem in problems)
            {
                output.WriteLine($"     {problem}");
            }
            output.WriteLine("     Install with 'winget install fmuecke.WsbMcp' or into a folder below C:\\Program Files.");
            return 1;
        }
        output.WriteLine($"OK   Executable location is safe: {exe}");

        if (!await WsbWorksAsync().ConfigureAwait(false))
        {
            output.WriteLine($"FAIL Windows Sandbox (wsb.exe) is not available. Enable it: {EnableSandboxCommand}");
            return 1;
        }
        output.WriteLine("OK   Windows Sandbox (wsb.exe) works");

        var configPath = BrokerConfig.DefaultConfigPath;
        if (File.Exists(configPath) && !options.Force)
        {
            output.WriteLine($"FAIL {configPath} already exists. Use --force to replace it, or 'wsb-mcp uninstall' first.");
            return 1;
        }
        // Validate the new configuration next to the real one (same folder, so the same location
        // checks apply) before touching anything that is running.
        Directory.CreateDirectory(BrokerConfig.StateDirectory);
        var candidate = configPath + ".new";
        File.WriteAllText(candidate, new JsonObject
        {
            ["agentAccount"] = options.Agent,
            ["allowedRoot"] = options.Root,
            ["pipeName"] = options.PipeName,
        }.ToJsonString(new System.Text.Json.JsonSerializerOptions { WriteIndented = true }));
        BrokerConfig config;
        try
        {
            config = BrokerConfig.Load(candidate);
        }
        catch (Exception ex) when (ex is InvalidOperationException or IOException or UnauthorizedAccessException)
        {
            File.Delete(candidate);
            output.WriteLine($"FAIL {ex.Message}");
            return 1;
        }

        // A running broker keeps its old configuration until it restarts: stop it first (it uses
        // the pipe from the old configuration), so the new one is what runs afterwards.
        if (await StopAsync(output).ConfigureAwait(false) != 0)
        {
            File.Delete(candidate);
            output.WriteLine("FAIL The running broker could not be stopped; the configuration was not changed.");
            return 1;
        }
        File.Move(candidate, configPath, overwrite: true);
        output.WriteLine($"OK   Wrote {configPath} (agent {config.AgentAccount}, root {config.AllowedRoot})");

        if (!AgentMayExecute(exe, config.AgentSid))
        {
            output.WriteLine($"WARN The permissions of '{exe}' do not obviously let {config.AgentAccount} run it. " +
                             "Run 'wsb-mcp diag' as the agent account to check.");
        }

        if (options.Autostart)
        {
            var (exit, text) = await RegisterTaskAsync(exe).ConfigureAwait(false);
            if (exit != 0)
            {
                output.WriteLine($"FAIL Could not register the logon task: {text}");
                return 1;
            }
            output.WriteLine($"OK   Registered logon task '{TaskName}'");
            var started = await StartBrokerAsync(config.PipeName, output).ConfigureAwait(false);
            if (started != 0)
            {
                return started;
            }
        }
        else
        {
            output.WriteLine($"     No autostart. Run the broker yourself: \"{exe}\" serve");
        }

        output.WriteLine();
        foreach (var line in ClaudeSideInstructions(config.AgentAccount, exe, config.PipeName))
        {
            output.WriteLine(line);
        }
        return 0;
    }

    /// <summary>What the agent has to do next. The plugin always uses the default pipe.</summary>
    internal static IEnumerable<string> ClaudeSideInstructions(string agent, string exe, string pipeName)
    {
        var defaultPipe = string.Equals(pipeName, BrokerConfig.DefaultPipeName, StringComparison.OrdinalIgnoreCase);
        yield return $"Next, as {agent}, in Claude Code:";
        if (defaultPipe)
        {
            yield return "  /plugin marketplace add fmuecke/windows-sandbox-mcp";
            yield return "  /plugin install wsb-mcp@windows-sandbox-mcp";
            yield return "or register it directly:";
            yield return $"  claude mcp add --scope user wsb -- \"{exe}\" proxy";
        }
        else
        {
            yield return $"  claude mcp add --scope user wsb -- \"{exe}\" proxy --pipe {pipeName}";
            yield return $"(The plugin always connects to the default pipe '{BrokerConfig.DefaultPipeName}', " +
                         $"so with the custom pipe '{pipeName}' register the server directly as above.)";
        }
    }

    public static Task<int> StartAsync(TextWriter output) =>
        StartBrokerAsync(TryLoadPipeName() ?? BrokerConfig.DefaultPipeName, output);

    public static async Task<int> StopAsync(TextWriter output)
    {
        var pipeName = TryLoadPipeName() ?? BrokerConfig.DefaultPipeName;
        if (!StopSignal.TrySignal(pipeName))
        {
            output.WriteLine(PipeExists(pipeName)
                ? $"FAIL A broker serves pipe '{pipeName}' but its stop event cannot be opened (another account's broker?)."
                : "OK   The broker is not running.");
            return PipeExists(pipeName) ? 1 : 0;
        }
        output.WriteLine("     Stopping the broker (and its guest)...");
        // The pipe closes before the broker has finished shutting down. Only when the process has
        // exited does its stop event disappear; a new broker started earlier would find the old
        // event and refuse to start (and the task would still count as running).
        if (await WaitAsync(() => !PipeExists(pipeName) && !StopSignal.Exists(pipeName), TimeSpan.FromSeconds(90))
                .ConfigureAwait(false))
        {
            output.WriteLine("OK   The broker stopped.");
            return 0;
        }
        output.WriteLine("FAIL The broker did not stop within 90 s; see broker.log.");
        return 1;
    }

    public static async Task<int> UninstallAsync(bool keepConfig, TextWriter output)
    {
        if (await StopAsync(output).ConfigureAwait(false) != 0)
        {
            return 1;
        }
        var (exit, text) = await RunToolAsync("schtasks.exe", ["/Delete", "/TN", TaskName, "/F"]).ConfigureAwait(false);
        output.WriteLine(exit == 0 ? $"OK   Removed logon task '{TaskName}'" : $"     No logon task removed ({text.Trim()})");
        if (!keepConfig && Directory.Exists(BrokerConfig.StateDirectory))
        {
            foreach (var name in new[] { "config.json", "broker.log", "guest.id" })
            {
                File.Delete(Path.Combine(BrokerConfig.StateDirectory, name));
            }
            if (!Directory.EnumerateFileSystemEntries(BrokerConfig.StateDirectory).Any())
            {
                Directory.Delete(BrokerConfig.StateDirectory);
            }
            output.WriteLine($"OK   Removed configuration and log from {BrokerConfig.StateDirectory}");
        }
        output.WriteLine("     Remove the program with 'winget uninstall fmuecke.WsbMcp', and the Claude Code " +
                         "registration with '/plugin uninstall wsb-mcp' (or 'claude mcp remove wsb').");
        return 0;
    }

    /// <summary>Checks every link of the chain; works as the broker user and as the agent.</summary>
    public static async Task<int> DiagAsync(TextWriter output)
    {
        var failures = 0;
        void Report(bool ok, string text, string? fix = null)
        {
            output.WriteLine($"{(ok ? "OK  " : "FAIL")} {text}");
            if (!ok)
            {
                failures++;
                if (fix is not null)
                {
                    output.WriteLine($"     -> {fix}");
                }
            }
        }

        var identity = WindowsIdentity.GetCurrent();
        output.WriteLine($"     wsb-mcp {ToolCatalog.Version}, running as {identity.Name}{(IsElevated() ? " (elevated)" : "")}");
        var exe = ExecutablePath();
        var configured = File.Exists(BrokerConfig.DefaultConfigPath);

        if (configured)
        {
            output.WriteLine("     Broker account (configuration found):");
            var problems = SafeLocation.FindProblems(exe, identity.User!);
            Report(problems.Count == 0, $"Executable location is safe: {exe}",
                problems.Count == 0 ? null : string.Join("; ", problems));
            Report(await WsbWorksAsync().ConfigureAwait(false), "Windows Sandbox (wsb.exe) works", EnableSandboxCommand);
            BrokerConfig? config = null;
            try
            {
                config = BrokerConfig.Load(BrokerConfig.DefaultConfigPath);
                Report(true, $"Configuration valid: agent {config.AgentAccount}, root {config.AllowedRoot}");
            }
            catch (Exception ex) when (ex is InvalidOperationException or IOException or UnauthorizedAccessException)
            {
                Report(false, $"Configuration {BrokerConfig.DefaultConfigPath}: {ex.Message}", "Fix it, or run 'wsb-mcp setup --force'.");
            }
            var (exit, xml) = await RunToolAsync("schtasks.exe", ["/Query", "/TN", TaskName, "/XML"]).ConfigureAwait(false);
            Report(exit == 0, $"Logon task '{TaskName}' registered", "Run 'wsb-mcp setup --force' (or start the broker by hand with 'wsb-mcp serve').");
            if (exit == 0)
            {
                Report(xml.Contains(exe, StringComparison.OrdinalIgnoreCase), "Logon task runs this executable",
                    "The task points elsewhere (old install?). Run 'wsb-mcp setup --force'.");
            }
            var pipeName = config?.PipeName ?? BrokerConfig.DefaultPipeName;
            Report(PipeExists(pipeName), $"Broker is running (pipe '{pipeName}')", "Run 'wsb-mcp start'; if it stops again, see broker.log.");
        }
        else
        {
            output.WriteLine("     Agent account (no broker configuration for this account):");
            var pipeName = BrokerConfig.DefaultPipeName;
            if (!PipeExists(pipeName))
            {
                Report(false, $"Broker is running (pipe '{pipeName}')",
                    "Ask the broker user to run 'wsb-mcp start' (or 'wsb-mcp setup' if it was never set up).");
            }
            else
            {
                var (ok, detail) = await HandshakeAsync(pipeName).ConfigureAwait(false);
                Report(ok, $"Broker accepts this account: {detail}",
                    "Check that the broker's agentAccount is this account, and that no other session is connected.");
            }
        }
        return failures == 0 ? 0 : 1;
    }

    // --- helpers --------------------------------------------------------------------------

    internal static string BuildTaskXml(string executable, string userName)
    {
        XNamespace ns = "http://schemas.microsoft.com/windows/2004/02/mit/task";
        var conhost = Path.Combine(Environment.SystemDirectory, "conhost.exe");
        var task = new XElement(ns + "Task", new XAttribute("version", "1.2"),
            new XElement(ns + "RegistrationInfo",
                new XElement(ns + "Description", "Runs the wsb-mcp broker in this user's desktop session (created by 'wsb-mcp setup').")),
            new XElement(ns + "Triggers",
                new XElement(ns + "LogonTrigger", new XElement(ns + "Enabled", "true"), new XElement(ns + "UserId", userName))),
            new XElement(ns + "Principals",
                new XElement(ns + "Principal", new XAttribute("id", "Author"),
                    new XElement(ns + "UserId", userName),
                    new XElement(ns + "LogonType", "InteractiveToken"),
                    new XElement(ns + "RunLevel", "LeastPrivilege"))),
            new XElement(ns + "Settings",
                new XElement(ns + "MultipleInstancesPolicy", "IgnoreNew"),
                new XElement(ns + "DisallowStartIfOnBatteries", "false"),
                new XElement(ns + "StopIfGoingOnBatteries", "false"),
                new XElement(ns + "AllowHardTerminate", "true"),
                new XElement(ns + "StartWhenAvailable", "false"),
                new XElement(ns + "IdleSettings",
                    new XElement(ns + "StopOnIdleEnd", "false"), new XElement(ns + "RestartOnIdle", "false")),
                new XElement(ns + "AllowStartOnDemand", "true"),
                new XElement(ns + "Enabled", "true"),
                new XElement(ns + "Hidden", "false"),
                new XElement(ns + "ExecutionTimeLimit", "PT0S"),
                new XElement(ns + "RestartOnFailure", new XElement(ns + "Interval", "PT1M"), new XElement(ns + "Count", "3"))),
            new XElement(ns + "Actions", new XAttribute("Context", "Author"),
                new XElement(ns + "Exec",
                    new XElement(ns + "Command", conhost),
                    new XElement(ns + "Arguments", $"--headless \"{executable}\" serve"))));
        return new XDeclaration("1.0", "UTF-16", null) + Environment.NewLine + task;
    }

    private static async Task<(int Exit, string Output)> RegisterTaskAsync(string exe)
    {
        var file = Path.Combine(BrokerConfig.StateDirectory, "task.xml");
        await File.WriteAllTextAsync(file, BuildTaskXml(exe, WindowsIdentity.GetCurrent().Name), Encoding.Unicode)
            .ConfigureAwait(false);
        try
        {
            return await RunToolAsync("schtasks.exe", ["/Create", "/TN", TaskName, "/XML", file, "/F"]).ConfigureAwait(false);
        }
        finally
        {
            File.Delete(file);
        }
    }

    private static async Task<int> StartBrokerAsync(string pipeName, TextWriter output)
    {
        if (PipeExists(pipeName))
        {
            output.WriteLine("OK   The broker is already running.");
            return 0;
        }
        // Task Scheduler silently ignores /Run while a previous instance of the task (for example
        // one still shutting down) counts as running, so ask again until the pipe appears.
        var watch = Stopwatch.StartNew();
        while (watch.Elapsed < TimeSpan.FromSeconds(30))
        {
            var (exit, text) = await RunToolAsync("schtasks.exe", ["/Run", "/TN", TaskName]).ConfigureAwait(false);
            if (exit != 0)
            {
                output.WriteLine($"FAIL Could not start the logon task '{TaskName}': {text.Trim()} Run 'wsb-mcp setup' first.");
                return 1;
            }
            if (await WaitAsync(() => PipeExists(pipeName), TimeSpan.FromSeconds(5)).ConfigureAwait(false))
            {
                output.WriteLine("OK   The broker is running.");
                return 0;
            }
        }
        output.WriteLine($"FAIL The broker did not come up within 30 s; see {Path.Combine(BrokerConfig.StateDirectory, "broker.log")}.");
        return 1;
    }

    private static async Task<(bool Ok, string Detail)> HandshakeAsync(string pipeName)
    {
        try
        {
            await using var pipe = new NamedPipeClientStream(
                ".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous, TokenImpersonationLevel.Identification);
            await pipe.ConnectAsync(2000).ConfigureAwait(false);
            await pipe.WriteAsync(Encoding.UTF8.GetBytes(
                """{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}""" + "\n"))
                .ConfigureAwait(false);
            var line = await new LineReader(pipe, McpSession.MaxMessageBytes).ReadLineAsync(CancellationToken.None)
                .WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(false);
            if (line is null)
            {
                return (false, "the broker closed the connection (configured for a different agent account?)");
            }
            var version = JsonNode.Parse(line)?["result"]?["serverInfo"]?["version"]?.GetValue<string>();
            return (true, $"wsb-mcp broker {version}");
        }
        catch (TimeoutException)
        {
            return (false, "no answer (another session is connected?)");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Text.Json.JsonException)
        {
            return (false, ex.Message);
        }
    }

    private static async Task<bool> WsbWorksAsync()
    {
        try
        {
            var result = await new WsbCli("wsb.exe").RunAsync(["list"], TimeSpan.FromSeconds(30), CancellationToken.None)
                .ConfigureAwait(false);
            return !result.TimedOut && result.ExitCode == 0;
        }
        catch (Win32Exception)
        {
            return false; // wsb.exe not found.
        }
    }

    /// <summary>Heuristic: an allow ACE granting read+execute to the agent or a group every user is in.</summary>
    private static bool AgentMayExecute(string exe, SecurityIdentifier agent)
    {
        const FileSystemRights needed = FileSystemRights.ReadAndExecute;
        SecurityIdentifier[] candidates =
        [
            agent,
            new(WellKnownSidType.BuiltinUsersSid, null),
            new(WellKnownSidType.AuthenticatedUserSid, null),
            new(WellKnownSidType.WorldSid, null),
            new(WellKnownSidType.InteractiveSid, null),
        ];
        var security = new FileInfo(exe).GetAccessControl();
        return security.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().Any(rule =>
            rule.AccessControlType == AccessControlType.Allow &&
            (rule.PropagationFlags & PropagationFlags.InheritOnly) == 0 &&
            rule.IdentityReference is SecurityIdentifier sid && candidates.Contains(sid) &&
            (SafeLocation.Expand(rule.FileSystemRights) & needed) == needed);
    }

    internal static string ExecutablePath()
    {
        var path = Environment.ProcessPath ?? throw new InvalidOperationException("Cannot determine the executable path.");
        using var handle = Native.TryOpen(path, Native.FILE_READ_ATTRIBUTES,
            Native.FILE_SHARE_READ | Native.FILE_SHARE_WRITE | Native.FILE_SHARE_DELETE, out _);
        // Resolve links (e.g. the winget Links shim) so the task and checks use the real file.
        return handle is null ? path : PathValidator.NormalizeFinalPath(Native.GetFinalPath(handle)) ?? path;
    }

    private static bool IsElevated() =>
        new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);

    internal static bool PipeExists(string pipeName) =>
        Directory.EnumerateFiles(@"\\.\pipe\").Any(p =>
            string.Equals(Path.GetFileName(p), pipeName, StringComparison.OrdinalIgnoreCase));

    private static string? TryLoadPipeName()
    {
        try
        {
            return File.Exists(BrokerConfig.DefaultConfigPath)
                ? JsonNode.Parse(File.ReadAllText(BrokerConfig.DefaultConfigPath))?["pipeName"]?.GetValue<string>()
                : null;
        }
        catch (Exception ex) when (ex is IOException or System.Text.Json.JsonException or InvalidOperationException)
        {
            return null;
        }
    }

    private static async Task<bool> WaitAsync(Func<bool> condition, TimeSpan limit)
    {
        var watch = Stopwatch.StartNew();
        while (!condition())
        {
            if (watch.Elapsed > limit)
            {
                return false;
            }
            await Task.Delay(250).ConfigureAwait(false);
        }
        return true;
    }

    internal static async Task<(int Exit, string Output)> RunToolAsync(string file, IEnumerable<string> arguments)
    {
        var info = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, file))
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        foreach (var argument in arguments)
        {
            info.ArgumentList.Add(argument);
        }
        using var process = Process.Start(info)!;
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync().ConfigureAwait(false);
        return (process.ExitCode, (await stdout.ConfigureAwait(false)) + (await stderr.ConfigureAwait(false)));
    }
}
