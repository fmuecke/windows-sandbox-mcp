// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: MIT
// https://github.com/fmuecke/windows-sandbox-mcp
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using System.Security.AccessControl;
using System.Security.Principal;

namespace WsbMcp.Tests;

/// <summary>A scratch directory below the repo (not %TEMP%, which may be an 8.3 path).</summary>
internal sealed class WorkDir : IDisposable
{
    private readonly List<(string Path, FileSystemAccessRule Rule)> _denies = [];

    public WorkDir()
    {
        var repo = AppContext.BaseDirectory;
        while (!File.Exists(Path.Combine(repo, "SPEC.md")))
        {
            repo = Path.GetDirectoryName(repo) ?? throw new InvalidOperationException("repo root not found");
        }
        Root = Directory.CreateDirectory(Path.Combine(repo, "tests", ".work", Guid.NewGuid().ToString("N"))).FullName;
    }

    public string Root { get; }

    public string Dir(string relative) => Directory.CreateDirectory(Path.Combine(Root, relative)).FullName;

    public void Deny(string path, FileSystemRights rights)
    {
        var rule = new FileSystemAccessRule(WindowsIdentity.GetCurrent().User!, rights, AccessControlType.Deny);
        var info = new DirectoryInfo(path);
        var security = info.GetAccessControl();
        security.AddAccessRule(rule);
        info.SetAccessControl(security);
        _denies.Add((path, rule));
    }

    public static void CreateJunction(string link, string target)
    {
        using var process = Process.Start(new ProcessStartInfo("cmd.exe")
        {
            ArgumentList = { "/c", "mklink", "/J", link, target },
            RedirectStandardOutput = true,
            UseShellExecute = false,
        })!;
        process.WaitForExit();
        if (process.ExitCode != 0)
        {
            throw new InvalidOperationException($"mklink /J failed: {process.StandardOutput.ReadToEnd()}");
        }
    }

    public void Dispose()
    {
        foreach (var (path, rule) in _denies)
        {
            var info = new DirectoryInfo(path);
            var security = info.GetAccessControl();
            security.RemoveAccessRule(rule);
            info.SetAccessControl(security);
        }
        for (var attempt = 0; ; attempt++)
        {
            try
            {
                // Remove junctions first so we never recurse into their targets.
                foreach (var dir in Directory.EnumerateDirectories(Root, "*", SearchOption.AllDirectories)
                             .Where(d => new DirectoryInfo(d).LinkTarget is not null).ToList())
                {
                    Directory.Delete(dir);
                }
                Directory.Delete(Root, recursive: true);
                return;
            }
            catch (IOException) when (attempt < 5)
            {
                Thread.Sleep(100);
            }
        }
    }
}

/// <summary>
/// Client identity for in-process tests: the current user, with an Identification-level token
/// like the one a non-elevated broker gets from the pipe.
/// </summary>
internal sealed class SelfClient : IClientIdentity
{
    private const uint TokenQuery = 0x0008;
    private const int SecurityIdentification = 1;
    private const int TokenImpersonation = 2;

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool DuplicateTokenEx(SafeAccessTokenHandle existing, uint access, IntPtr attributes,
        int level, int type, out SafeAccessTokenHandle duplicate);

    public SelfClient()
    {
        using var self = WindowsIdentity.GetCurrent();
        if (!DuplicateTokenEx(self.AccessToken, TokenQuery, IntPtr.Zero, SecurityIdentification, TokenImpersonation,
                out var token))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }
        Token = token;
    }

    public string Name => WindowsIdentity.GetCurrent().Name;

    public SafeAccessTokenHandle Token { get; }
}

/// <summary>Controllable wall clock; timestamps/delays stay real.</summary>
internal sealed class ManualTime : TimeProvider
{
    private DateTimeOffset _now = new(2026, 11, 1, 12, 0, 0, TimeSpan.Zero);

    public override DateTimeOffset GetUtcNow() => _now;

    public void Advance(TimeSpan by) => _now += by;
}

/// <summary>In-process wsb.exe double with per-command handlers and a call log.</summary>
internal sealed class ScriptedWsb : IWsbCli
{
    public List<string[]> Calls { get; } = [];
    public List<string[]> Launches { get; } = [];
    public bool Running { get; set; }
    public bool OtherSandboxRunning { get; set; }
    public bool Session { get; set; }
    public int ShareFailuresBeforeReady { get; set; }
    public bool ShareAlwaysFails { get; set; }
    public Func<string[], WsbResult>? Exec { get; set; }

    /// <summary>Id of the (single) sandbox this double starts or lists.</summary>
    public string Id { get; set; } = "id-1";

    public Task<WsbResult> RunAsync(IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken cancellationToken)
    {
        var args = arguments.ToArray();
        Calls.Add(args);
        WsbResult result = args[0] switch
        {
            "list" => Ok(OtherSandboxRunning || Running
                ? $$"""{"WindowsSandboxEnvironments": [{"Id": "{{Id}}"}]}"""
                : """{"WindowsSandboxEnvironments": []}"""),
            "start" => Start(),
            "share" => Share(),
            "stop" => Stop(),
            "exec" => Exec?.Invoke(args) ?? DefaultExec(args),
            _ => new WsbResult(1, "unknown", false),
        };
        return Task.FromResult(result);
    }

    public Task<int?> LaunchAsync(IReadOnlyList<string> arguments, TimeSpan wait, CancellationToken cancellationToken)
    {
        Launches.Add(arguments.ToArray());
        if (arguments[0] == "connect")
        {
            Session = true;
        }
        return Task.FromResult<int?>(0);
    }

    public IEnumerable<string[]> CallsOf(string command) => Calls.Where(c => c[0] == command);

    private WsbResult Start()
    {
        Running = true;
        return Ok($$"""{"Id": "{{Id}}"}""");
    }

    private WsbResult Share()
    {
        if (ShareAlwaysFails || ShareFailuresBeforeReady-- > 0)
        {
            return new WsbResult(1, "not ready", false);
        }
        return Ok("");
    }

    private WsbResult Stop()
    {
        Running = false;
        Session = false;
        return Ok("");
    }

    private WsbResult DefaultExec(string[] args)
    {
        if (args[Array.IndexOf(args, "-r") + 1] == "ExistingLogin" && !Session)
        {
            return new WsbResult(SandboxManager.NoLogonSession, "A specified logon session does not exist. (0x80070520)", false);
        }
        return Ok("""{"ExitCode": 0}""");
    }

    public static WsbResult Ok(string output) => new(0, output, false);
}

/// <summary>In-memory guest record.</summary>
internal sealed class MemoryGuestRecord : IGuestRecord
{
    public string? Value { get; set; }

    public string? Read() => Value;

    public void Write(string id) => Value = id;

    public void Clear() => Value = null;
}

internal static class Fixtures
{
    /// <summary>
    /// The wsb-mcp.exe that process-level tests start. CI points WSB_MCP_EXE at the published,
    /// trimmed release exe, so the shipped binary is exercised, not only the test build.
    /// </summary>
    public static string WsbMcpExe =>
        Environment.GetEnvironmentVariable("WSB_MCP_EXE") is { Length: > 0 } exe
            ? exe
            : Path.Combine(AppContext.BaseDirectory, "wsb-mcp.exe");

    public static readonly SandboxOptions FastOptions = new(TimeSpan.FromSeconds(2), 600, TimeSpan.FromMinutes(30))
    {
        RetryInterval = TimeSpan.FromMilliseconds(10),
        SessionTimeout = TimeSpan.FromSeconds(1),
    };

    public static SandboxManager Manager(IWsbCli wsb, string root, TimeProvider? time = null, SandboxOptions? options = null) =>
        new(wsb, new PathValidator(root), options ?? FastOptions, NullBrokerLog.Instance, time ?? TimeProvider.System);
}
