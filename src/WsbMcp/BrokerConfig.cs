using System.Security.Principal;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace WsbMcp;

/// <summary>Host-only broker configuration. Never exposed to or changeable by the client.</summary>
public sealed partial class BrokerConfig
{
    public required string AgentAccount { get; init; }
    public required SecurityIdentifier AgentSid { get; init; }
    public required string AllowedRoot { get; init; }
    public required string PipeName { get; init; }
    public required TimeSpan IdleTimeout { get; init; }
    public required int MaxExecTimeoutSeconds { get; init; }
    public required TimeSpan StartupTimeout { get; init; }
    public required string LogPath { get; init; }
    public required string WsbPath { get; init; }

    private sealed class FileModel
    {
        public string? AgentAccount { get; set; }
        public string? AllowedRoot { get; set; }
        public string? PipeName { get; set; }
        public int? IdleTimeoutMinutes { get; set; }
        public int? MaxExecTimeoutSeconds { get; set; }
        public int? StartupTimeoutSeconds { get; set; }
        public string? LogPath { get; set; }
        public string? WsbPath { get; set; }
    }

    public static BrokerConfig Load(string configPath)
    {
        var configFullPath = Path.GetFullPath(configPath);
        FileModel model;
        try
        {
            model = JsonSerializer.Deserialize<FileModel>(File.ReadAllText(configFullPath), new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true,
                ReadCommentHandling = JsonCommentHandling.Skip,
                AllowTrailingCommas = true,
                UnmappedMemberHandling = System.Text.Json.Serialization.JsonUnmappedMemberHandling.Disallow,
            }) ?? throw new InvalidOperationException("Configuration is empty.");
        }
        catch (JsonException ex)
        {
            throw new InvalidOperationException($"Invalid configuration '{configFullPath}': {ex.Message}", ex);
        }

        var agentAccount = Require(model.AgentAccount, "agentAccount");
        SecurityIdentifier agentSid;
        try
        {
            agentSid = (SecurityIdentifier)new NTAccount(agentAccount).Translate(typeof(SecurityIdentifier));
        }
        catch (IdentityNotMappedException ex)
        {
            throw new InvalidOperationException($"agentAccount '{agentAccount}' does not exist.", ex);
        }
        if (agentSid == WindowsIdentity.GetCurrent().User)
        {
            throw new InvalidOperationException("agentAccount must differ from the broker account.");
        }

        var root = PathValidator.ResolveFinalDirectory(
            Environment.ExpandEnvironmentVariables(Require(model.AllowedRoot, "allowedRoot")));

        var pipeName = model.PipeName ?? "wsb-mcp";
        if (!PipeNamePattern().IsMatch(pipeName))
        {
            throw new InvalidOperationException("pipeName may only contain letters, digits, '.', '_' and '-' (max 64).");
        }

        var logPath = Path.GetFullPath(Environment.ExpandEnvironmentVariables(
            model.LogPath ?? @"%LOCALAPPDATA%\wsb-mcp\broker.log"));
        var logDirectory = Path.GetDirectoryName(logPath)!;
        Directory.CreateDirectory(logDirectory);

        // Anything the agent can write must not influence the trusted broker.
        RequireOutsideRoot("configuration file", Path.GetDirectoryName(configFullPath)!, root);
        RequireOutsideRoot("log directory", logDirectory, root);
        RequireOutsideRoot("broker executable", Path.GetDirectoryName(Environment.ProcessPath!)!, root);

        var wsbPath = model.WsbPath ?? "wsb.exe";
        if (Path.IsPathFullyQualified(wsbPath))
        {
            RequireOutsideRoot("wsbPath", Path.GetDirectoryName(wsbPath)!, root);
        }

        return new BrokerConfig
        {
            AgentAccount = agentAccount,
            AgentSid = agentSid,
            AllowedRoot = root,
            PipeName = pipeName,
            IdleTimeout = TimeSpan.FromMinutes(Range(model.IdleTimeoutMinutes ?? 30, 1, 24 * 60, "idleTimeoutMinutes")),
            MaxExecTimeoutSeconds = Range(model.MaxExecTimeoutSeconds ?? 1800, 1, 24 * 3600, "maxExecTimeoutSeconds"),
            StartupTimeout = TimeSpan.FromSeconds(Range(model.StartupTimeoutSeconds ?? 120, 10, 600, "startupTimeoutSeconds")),
            LogPath = logPath,
            WsbPath = wsbPath,
        };
    }

    private static void RequireOutsideRoot(string what, string directory, string root)
    {
        var final = PathValidator.ResolveFinalDirectory(directory);
        if (PathValidator.IsUnder(final, root))
        {
            throw new InvalidOperationException(
                $"The {what} ('{final}') is inside allowedRoot ('{root}'), where the agent may modify it. Move it elsewhere.");
        }
    }

    private static string Require(string? value, string name) =>
        string.IsNullOrWhiteSpace(value) ? throw new InvalidOperationException($"'{name}' is required.") : value;

    private static int Range(int value, int min, int max, string name) =>
        value < min || value > max ? throw new InvalidOperationException($"'{name}' must be between {min} and {max}.") : value;

    [GeneratedRegex("^[A-Za-z0-9._-]{1,64}$")]
    private static partial Regex PipeNamePattern();
}
