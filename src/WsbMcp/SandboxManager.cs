// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: MIT
// https://github.com/fmuecke/windows-sandbox-mcp
using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace WsbMcp;

public enum RunAs
{
    System,
    User,
}

public sealed record SandboxOptions(
    TimeSpan StartupTimeout,
    int MaxExecTimeoutSeconds,
    TimeSpan IdleTimeout)
{
    public TimeSpan RetryInterval { get; init; } = TimeSpan.FromSeconds(2);
    public TimeSpan SessionTimeout { get; init; } = TimeSpan.FromSeconds(60);
    public TimeSpan CliTimeout { get; init; } = TimeSpan.FromSeconds(60);
}

/// <summary>Owns at most one Windows Sandbox guest and serializes all operations on it.</summary>
public sealed class SandboxManager(
    IWsbCli wsb, PathValidator validator, SandboxOptions options, IBrokerLog log, TimeProvider time)
{
    public const string InputGuestPath = @"C:\SandboxIn";
    public const string OutputGuestPath = @"C:\SandboxOut";

    /// <summary>HRESULT 0x80070520: no logon session (no user session in the guest yet).</summary>
    internal const int NoLogonSession = unchecked((int)0x80070520);

    /// <summary>Hard-coded guest configuration (SPEC.md). Not influenced by any client input.</summary>
    internal const string GuestConfiguration =
        "<Configuration>" +
        "<Networking>Disable</Networking>" +
        "<vGPU>Disable</vGPU>" +
        "<ClipboardRedirection>Disable</ClipboardRedirection>" +
        "<AudioInput>Disable</AudioInput>" +
        "<VideoInput>Disable</VideoInput>" +
        "<PrinterRedirection>Disable</PrinterRedirection>" +
        "<ProtectedClient>Enable</ProtectedClient>" +
        "</Configuration>";

    private const int MaxGuestArgumentLength = 8000;

    private readonly SemaphoreSlim _gate = new(1, 1);
    private Guest? _guest;
    private DateTimeOffset _lastActivity = time.GetUtcNow();

    private sealed record Guest(
        string Id, DateTimeOffset StartedAt, long StartedTimestamp, string? InputHostPath, string? OutputHostPath)
    {
        public string DefaultWorkingDirectory =>
            OutputHostPath is not null ? OutputGuestPath : InputHostPath is not null ? InputGuestPath : @"C:\";
    }

    public bool IsRunning => _guest is not null;

    public async Task<JsonObject> StartAsync(
        string? inputPath, string? outputPath, IClientIdentity client, CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_guest is not null)
            {
                throw new ToolException($"A sandbox is already running ({_guest.Id}). Call sandbox_stop first.");
            }
            if ((await ListAsync(cancellationToken).ConfigureAwait(false)).Count != 0)
            {
                throw new ToolException(
                    "Another Windows Sandbox is already running on the host; refusing to attach to it.");
            }

            DirectoryLease? output = null;
            DirectoryLease? input = null;
            try
            {
                if (outputPath is not null)
                {
                    output = validator.Acquire(outputPath, DirectoryAccess.ReadWrite, client, "outputPath");
                }
                if (inputPath is not null)
                {
                    input = validator.Acquire(inputPath, DirectoryAccess.Read, client, "inputPath");
                    if (output is not null &&
                        string.Equals(input.FinalPath, output.FinalPath, StringComparison.OrdinalIgnoreCase))
                    {
                        input.Dispose();
                        input = null;
                    }
                }

                var startTimestamp = time.GetTimestamp();
                var startedAt = time.GetUtcNow();
                var start = await wsb.RunAsync(["start", "--config", GuestConfiguration], options.CliTimeout, cancellationToken)
                    .ConfigureAwait(false);
                if (start.TimedOut || start.ExitCode != 0)
                {
                    throw new ToolException($"wsb start failed (exit code {start.ExitCode}): {start.Output}");
                }
                var id = FindString(ParseJson(start.Output, "wsb start"), "Id")
                    ?? throw new ToolException($"wsb start did not return a sandbox id: {start.Output}");
                log.Write("guest.started", new JsonObject { ["id"] = id });

                try
                {
                    if (input is not null)
                    {
                        await ShareAsync(id, input.FinalPath, InputGuestPath, writable: false, startTimestamp, cancellationToken)
                            .ConfigureAwait(false);
                    }
                    if (output is not null)
                    {
                        await ShareAsync(id, output.FinalPath, OutputGuestPath, writable: true, startTimestamp, cancellationToken)
                            .ConfigureAwait(false);
                    }
                    if (input is null && output is null)
                    {
                        await WaitUntilReadyAsync(id, startTimestamp, cancellationToken).ConfigureAwait(false);
                    }
                }
                catch
                {
                    await StopGuestQuietlyAsync(id, "start failed").ConfigureAwait(false);
                    throw;
                }

                _guest = new Guest(id, startedAt, startTimestamp, input?.FinalPath, output?.FinalPath);
                var result = new JsonObject
                {
                    ["id"] = id,
                    ["startupSeconds"] = Seconds(time.GetElapsedTime(startTimestamp)),
                };
                if (input is not null)
                {
                    result["inputGuestPath"] = InputGuestPath;
                }
                if (output is not null)
                {
                    result["outputGuestPath"] = OutputGuestPath;
                }
                return result;
            }
            finally
            {
                // Shares are established (or the guest is gone); release the TOCTOU pins.
                input?.Dispose();
                output?.Dispose();
            }
        }
        finally
        {
            Touch();
            _gate.Release();
        }
    }

    public async Task<JsonObject> ExecAsync(
        string command, string? workingDirectory, RunAs runAs, int? timeoutSeconds, CancellationToken cancellationToken)
    {
        ValidateGuestArgument(command, "command");
        if (workingDirectory is not null)
        {
            ValidateGuestArgument(workingDirectory, "workingDirectory");
        }
        var seconds = timeoutSeconds ?? options.MaxExecTimeoutSeconds;
        if (seconds < 1 || seconds > options.MaxExecTimeoutSeconds)
        {
            throw new ToolException($"timeoutSeconds must be between 1 and {options.MaxExecTimeoutSeconds}.");
        }
        var timeout = TimeSpan.FromSeconds(seconds);

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var guest = RequireGuest();
            string[] arguments =
            [
                "exec", "--id", guest.Id,
                "-d", workingDirectory ?? guest.DefaultWorkingDirectory,
                "-r", runAs == RunAs.System ? "System" : "ExistingLogin",
                "-c", command,
            ];

            var execTimestamp = time.GetTimestamp();
            var result = await wsb.RunAsync(arguments, timeout, cancellationToken).ConfigureAwait(false);
            if (runAs == RunAs.User && !result.TimedOut && result.ExitCode == NoLogonSession)
            {
                result = await ConnectAndRetryAsync(guest, arguments, timeout, cancellationToken).ConfigureAwait(false);
            }
            var duration = Seconds(time.GetElapsedTime(execTimestamp));

            if (result.TimedOut)
            {
                return new JsonObject { ["exitCode"] = null, ["timedOut"] = true, ["durationSeconds"] = duration };
            }
            if (result.ExitCode != 0)
            {
                throw new ToolException(
                    $"wsb exec could not launch the command (wsb exit code 0x{result.ExitCode:X8}): {result.Output}");
            }

            var root = ParseJson(result.Output, "wsb exec");
            if (root is not JsonObject obj || !TryGetInt(obj, "ExitCode", out var exitCode))
            {
                throw new ToolException($"wsb exec did not report a guest exit code: {result.Output}");
            }
            return new JsonObject { ["exitCode"] = exitCode, ["timedOut"] = false, ["durationSeconds"] = duration };
        }
        finally
        {
            Touch();
            _gate.Release();
        }
    }

    public async Task<JsonObject> StatusAsync(CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var result = new JsonObject();
            if (_guest is not null)
            {
                var ids = await ListAsync(cancellationToken).ConfigureAwait(false);
                if (!ids.Contains(_guest.Id, StringComparer.OrdinalIgnoreCase))
                {
                    log.Write("guest.vanished", new JsonObject { ["id"] = _guest.Id });
                    result["note"] = $"Sandbox {_guest.Id} is no longer running (stopped outside the broker).";
                    _guest = null;
                }
            }
            result["running"] = _guest is not null;
            if (_guest is not null)
            {
                result["id"] = _guest.Id;
                result["startedAt"] = _guest.StartedAt.ToString("o", CultureInfo.InvariantCulture);
                result["lastActivityAt"] = _lastActivity.ToString("o", CultureInfo.InvariantCulture);
                if (_guest.InputHostPath is not null)
                {
                    result["inputHostPath"] = _guest.InputHostPath;
                    result["inputGuestPath"] = InputGuestPath;
                }
                if (_guest.OutputHostPath is not null)
                {
                    result["outputHostPath"] = _guest.OutputHostPath;
                    result["outputGuestPath"] = OutputGuestPath;
                }
            }
            return result;
        }
        finally
        {
            Touch();
            _gate.Release();
        }
    }

    public async Task<JsonObject> StopAsync(string reason, CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return await StopCoreAsync(reason, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            Touch();
            _gate.Release();
        }
    }

    /// <summary>Stops the guest if no call is in progress and the idle timeout has elapsed.</summary>
    public async Task StopIfIdleAsync()
    {
        if (!await _gate.WaitAsync(0).ConfigureAwait(false))
        {
            return; // A tool call is in progress; that counts as activity.
        }
        try
        {
            if (_guest is not null && time.GetUtcNow() - _lastActivity >= options.IdleTimeout)
            {
                await StopCoreAsync("idle timeout", CancellationToken.None).ConfigureAwait(false);
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    private async Task<JsonObject> StopCoreAsync(string reason, CancellationToken cancellationToken)
    {
        if (_guest is null)
        {
            return new JsonObject { ["stopped"] = false };
        }
        var guest = _guest;
        var stop = await wsb.RunAsync(["stop", "--id", guest.Id], options.CliTimeout, cancellationToken).ConfigureAwait(false);
        if (stop.TimedOut || stop.ExitCode != 0)
        {
            var ids = await ListAsync(cancellationToken).ConfigureAwait(false);
            if (ids.Contains(guest.Id, StringComparer.OrdinalIgnoreCase))
            {
                log.Write("guest.stop_failed", new JsonObject { ["id"] = guest.Id, ["output"] = stop.Output });
                throw new ToolException($"wsb stop failed (exit code {stop.ExitCode}): {stop.Output}");
            }
        }
        _guest = null;
        var total = Seconds(time.GetElapsedTime(guest.StartedTimestamp));
        log.Write("guest.stopped", new JsonObject { ["id"] = guest.Id, ["reason"] = reason, ["totalSeconds"] = total });
        return new JsonObject { ["stopped"] = true, ["totalSeconds"] = total };
    }

    private async Task StopGuestQuietlyAsync(string id, string reason)
    {
        try
        {
            var stop = await wsb.RunAsync(["stop", "--id", id], options.CliTimeout, CancellationToken.None).ConfigureAwait(false);
            log.Write("guest.stopped", new JsonObject { ["id"] = id, ["reason"] = reason, ["exitCode"] = stop.ExitCode });
        }
        catch (Exception ex) when (ex is ToolException or IOException or InvalidOperationException)
        {
            log.Write("guest.stop_failed", new JsonObject { ["id"] = id, ["reason"] = reason, ["error"] = ex.Message });
        }
    }

    private async Task ShareAsync(
        string id, string hostPath, string guestPath, bool writable, long startTimestamp, CancellationToken cancellationToken)
    {
        List<string> arguments = ["share", "--id", id, "-f", hostPath, "-s", guestPath];
        if (writable)
        {
            arguments.Add("-w");
        }
        while (true)
        {
            var share = await wsb.RunAsync(arguments, options.CliTimeout, cancellationToken).ConfigureAwait(false);
            if (!share.TimedOut && share.ExitCode == 0)
            {
                return;
            }
            if (time.GetElapsedTime(startTimestamp) >= options.StartupTimeout)
            {
                throw new ToolException($"Windows Sandbox did not accept the share of '{hostPath}': {share.Output}");
            }
            await Task.Delay(options.RetryInterval, time, cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task WaitUntilReadyAsync(string id, long startTimestamp, CancellationToken cancellationToken)
    {
        string[] probe = ["exec", "--id", id, "-r", "System", "-c", "cmd.exe /c exit 0"];
        while (true)
        {
            var result = await wsb.RunAsync(probe, options.CliTimeout, cancellationToken).ConfigureAwait(false);
            if (!result.TimedOut && result.ExitCode == 0)
            {
                return;
            }
            if (time.GetElapsedTime(startTimestamp) >= options.StartupTimeout)
            {
                throw new ToolException($"Windows Sandbox did not become ready: {result.Output}");
            }
            await Task.Delay(options.RetryInterval, time, cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task<WsbResult> ConnectAndRetryAsync(
        Guest guest, string[] arguments, TimeSpan timeout, CancellationToken cancellationToken)
    {
        var connectExit = await wsb.LaunchAsync(["connect", "--id", guest.Id], TimeSpan.FromSeconds(15), cancellationToken)
            .ConfigureAwait(false);
        log.Write("guest.connect", new JsonObject { ["id"] = guest.Id, ["exitCode"] = connectExit });

        var connectTimestamp = time.GetTimestamp();
        while (true)
        {
            await Task.Delay(options.RetryInterval, time, cancellationToken).ConfigureAwait(false);
            var result = await wsb.RunAsync(arguments, timeout, cancellationToken).ConfigureAwait(false);
            if (result.TimedOut || result.ExitCode != NoLogonSession)
            {
                return result;
            }
            if (time.GetElapsedTime(connectTimestamp) >= options.SessionTimeout)
            {
                throw new ToolException(
                    $"No user session in the guest {Seconds(options.SessionTimeout)} s after 'wsb connect'. " +
                    "runAs 'user' needs the broker to run on an interactive desktop.");
            }
        }
    }

    private async Task<List<string>> ListAsync(CancellationToken cancellationToken)
    {
        var list = await wsb.RunAsync(["list"], options.CliTimeout, cancellationToken).ConfigureAwait(false);
        if (list.TimedOut || list.ExitCode != 0)
        {
            throw new ToolException($"wsb list failed (exit code {list.ExitCode}): {list.Output}");
        }
        var ids = new List<string>();
        if (ParseJson(list.Output, "wsb list") is JsonObject root &&
            TryGetProperty(root, "WindowsSandboxEnvironments", out var environments) &&
            environments is JsonArray array)
        {
            foreach (var environment in array)
            {
                ids.Add(environment is null ? string.Empty : FindString(environment, "Id") ?? string.Empty);
            }
            return ids;
        }
        throw new ToolException($"Unexpected wsb list output: {list.Output}");
    }

    private Guest RequireGuest() =>
        _guest ?? throw new ToolException("No sandbox is running. Call sandbox_start first.");

    private void Touch() => _lastActivity = time.GetUtcNow();

    internal static void ValidateGuestArgument(string value, string name)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ToolException($"{name} must not be empty.");
        }
        if (value.Contains('\0'))
        {
            throw new ToolException($"{name} must not contain NUL characters.");
        }
        if (value.Length > MaxGuestArgumentLength)
        {
            throw new ToolException($"{name} must not exceed {MaxGuestArgumentLength} characters.");
        }
        // wsb.exe parses its argv: '-' would start an option, '@' a response file read on the host.
        if (value[0] is '-' or '@')
        {
            throw new ToolException($"{name} must not start with '-' or '@'.");
        }
    }

    private static JsonNode? ParseJson(string output, string what)
    {
        try
        {
            return JsonNode.Parse(output, documentOptions: new JsonDocumentOptions { MaxDepth = 16 });
        }
        catch (JsonException)
        {
            throw new ToolException($"{what} returned non-JSON output: {output}");
        }
    }

    private static string? FindString(JsonNode? node, string name)
    {
        switch (node)
        {
            case JsonObject obj:
                foreach (var (key, value) in obj)
                {
                    if (string.Equals(key, name, StringComparison.OrdinalIgnoreCase) &&
                        value is JsonValue v && v.TryGetValue<string>(out var s) && s.Length > 0)
                    {
                        return s;
                    }
                }
                foreach (var (_, value) in obj)
                {
                    if (FindString(value, name) is { } nested)
                    {
                        return nested;
                    }
                }
                return null;
            case JsonArray array:
                foreach (var item in array)
                {
                    if (FindString(item, name) is { } nested)
                    {
                        return nested;
                    }
                }
                return null;
            default:
                return null;
        }
    }

    private static bool TryGetProperty(JsonObject obj, string name, out JsonNode? value)
    {
        foreach (var (key, candidate) in obj)
        {
            if (string.Equals(key, name, StringComparison.OrdinalIgnoreCase))
            {
                value = candidate;
                return true;
            }
        }
        value = null;
        return false;
    }

    private static bool TryGetInt(JsonObject obj, string name, out int value)
    {
        value = 0;
        if (!TryGetProperty(obj, name, out var node) || node is not JsonValue v || !v.TryGetValue(out long number) ||
            number < int.MinValue || number > uint.MaxValue)
        {
            return false;
        }
        value = unchecked((int)number); // Windows exit codes are DWORDs; report them as signed like $LASTEXITCODE.
        return true;
    }

    private static double Seconds(TimeSpan span) => Math.Round(span.TotalSeconds, 2);
}
