using System.Diagnostics;
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

/// <summary>Client identity for in-process tests: runs as the current user.</summary>
internal sealed class SelfClient : IClientIdentity
{
    public string Name => WindowsIdentity.GetCurrent().Name;

    public void RunAsClient(Action action) => action();
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

    public Task<WsbResult> RunAsync(IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken cancellationToken)
    {
        var args = arguments.ToArray();
        Calls.Add(args);
        WsbResult result = args[0] switch
        {
            "list" => Ok(OtherSandboxRunning || Running
                ? """{"WindowsSandboxEnvironments": [{"Id": "id-1"}]}"""
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
        return Ok("""{"Id": "id-1"}""");
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

internal static class Fixtures
{
    public static readonly SandboxOptions FastOptions = new(TimeSpan.FromSeconds(2), 600, TimeSpan.FromMinutes(30))
    {
        RetryInterval = TimeSpan.FromMilliseconds(10),
        SessionTimeout = TimeSpan.FromSeconds(1),
    };

    public static SandboxManager Manager(IWsbCli wsb, string root, TimeProvider? time = null, SandboxOptions? options = null) =>
        new(wsb, new PathValidator(root), options ?? FastOptions, NullBrokerLog.Instance, time ?? TimeProvider.System);
}
