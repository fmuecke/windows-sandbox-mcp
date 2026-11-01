using System.Globalization;
using System.Text.Json.Nodes;

namespace WsbMcp;

/// <summary>Tool names, descriptions and input schemas advertised to the client.</summary>
public sealed class ToolCatalog
{
    public const string Version = "0.1.0";
    public const string Start = "sandbox_start";
    public const string Exec = "sandbox_exec";
    public const string Status = "sandbox_status";
    public const string Stop = "sandbox_stop";

    public const string Instructions =
        "Runs risky commands in a fresh, disposable, offline Windows Sandbox guest. " +
        "Typical flow: sandbox_start (map folders) -> sandbox_exec (redirect output to files in " +
        SandboxManager.OutputGuestPath + ") -> read those files on the host -> sandbox_stop. " +
        "Guest commands run elevated; the guest has no network.";

    public ToolCatalog(string allowedRoot, int maxExecTimeoutSeconds, TimeSpan idleTimeout)
    {
        var idleMinutes = ((int)idleTimeout.TotalMinutes).ToString(CultureInfo.InvariantCulture);
        Definitions = new JsonArray(
            Tool(Start,
                "Start a fresh, disposable Windows Sandbox guest with networking disabled. Optionally map a host " +
                $"input folder read-only at {SandboxManager.InputGuestPath} and a host output folder writable at " +
                $"{SandboxManager.OutputGuestPath}. Host folders must be below '{allowedRoot}' and accessible to you " +
                "(read for input, read/write for output). If both are the same folder it is mapped once, writable, at " +
                $"{SandboxManager.OutputGuestPath}. Host changes are visible to the guest live. Only one sandbox can run; " +
                $"it is stopped when you disconnect or after {idleMinutes} minutes without tool calls. Fails if any " +
                "Windows Sandbox is already running on the host.",
                new JsonObject
                {
                    ["inputPath"] = StringProperty("Absolute host path of the folder to map read-only."),
                    ["outputPath"] = StringProperty("Absolute host path of the folder to map writable."),
                }),
            Tool(Exec,
                "Run a command line in the guest and wait for it to finish. Returns only the guest process exit code: " +
                "stdout/stderr are NOT returned. Redirect them to a file in the output folder, e.g. " +
                $"'cmd.exe /c mytest.exe > {SandboxManager.OutputGuestPath}\\log.txt 2>&1', then read the file from the " +
                "host output folder. runAs 'system' runs as NT AUTHORITY\\SYSTEM; 'user' runs as the guest user " +
                "WDAGUtilityAccount, which is also elevated (its first use opens a sandbox window on the host). " +
                "On timeout the result has timedOut=true and the guest process keeps running. The command must not " +
                "start with '-' or '@'.",
                new JsonObject
                {
                    ["command"] = StringProperty("Command line to run in the guest, e.g. 'cmd.exe /c ...' or 'powershell.exe -File ...'."),
                    ["workingDirectory"] = StringProperty(
                        $"Guest working directory. Default: {SandboxManager.OutputGuestPath} if mapped, else " +
                        $"{SandboxManager.InputGuestPath} if mapped, else C:\\."),
                    ["runAs"] = new JsonObject
                    {
                        ["type"] = "string",
                        ["enum"] = new JsonArray("system", "user"),
                        ["description"] = "Guest identity. Default: system. Both are elevated.",
                    },
                    ["timeoutSeconds"] = new JsonObject
                    {
                        ["type"] = "integer",
                        ["minimum"] = 1,
                        ["maximum"] = maxExecTimeoutSeconds,
                        ["description"] = $"Maximum wait in seconds. Default: {maxExecTimeoutSeconds}.",
                    },
                },
                "command"),
            Tool(Status, "Report whether the sandbox is running, its id, timestamps and mapped folders.", new JsonObject()),
            Tool(Stop, "Stop and discard the sandbox guest. Succeeds with stopped=false if none is running.", new JsonObject()));
        Names = new HashSet<string>(StringComparer.Ordinal) { Start, Exec, Status, Stop };
    }

    public JsonArray Definitions { get; }

    public IReadOnlySet<string> Names { get; }

    private static JsonObject Tool(string name, string description, JsonObject properties, params string[] required)
    {
        var schema = new JsonObject
        {
            ["type"] = "object",
            ["properties"] = properties,
            ["additionalProperties"] = false,
        };
        if (required.Length > 0)
        {
            schema["required"] = new JsonArray(required.Select(r => (JsonNode)r).ToArray());
        }
        return new JsonObject { ["name"] = name, ["description"] = description, ["inputSchema"] = schema };
    }

    private static JsonObject StringProperty(string description) =>
        new() { ["type"] = "string", ["description"] = description };
}
