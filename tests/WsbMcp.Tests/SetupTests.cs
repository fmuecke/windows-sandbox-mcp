// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: MIT
// https://github.com/fmuecke/windows-sandbox-mcp
using System.Diagnostics;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Xml.Linq;

namespace WsbMcp.Tests;

/// <summary>Safe-location rule, logon task definition, stop signal and crash recovery.</summary>
public sealed class SetupTests : IDisposable
{
    private static readonly SecurityIdentifier Self = WindowsIdentity.GetCurrent().User!;
    private static readonly SecurityIdentifier Users = new(WellKnownSidType.BuiltinUsersSid, null);
    private static readonly SecurityIdentifier Admins = new(WellKnownSidType.BuiltinAdministratorsSid, null);
    private static readonly SecurityIdentifier Stranger = new("S-1-5-21-1-2-3-4242");

    private readonly WorkDir _work = new();

    public void Dispose() => _work.Dispose();

    [Test]
    public void SystemExecutableIsInASafeLocation()
    {
        var problems = SafeLocation.FindProblems(Path.Combine(Environment.SystemDirectory, "cmd.exe"), Self);
        Assert.Equal(0, problems.Count, string.Join(" | ", problems));
        // Program Files (where winget installs machine-scope packages) with its default ACL.
        var dotnet = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "dotnet", "dotnet.exe");
        problems = SafeLocation.FindProblems(dotnet, Self);
        Assert.Equal(0, problems.Count, string.Join(" | ", problems));
    }

    [Test]
    public void ExecutableBelowAgentWritableTreeIsRejected()
    {
        // A folder that grants Users Modify, like a hand-made C:\Tools inheriting the C:\ ACL.
        var dir = new DirectoryInfo(_work.Dir("bin"));
        var security = dir.GetAccessControl();
        security.AddAccessRule(new FileSystemAccessRule(Users, FileSystemRights.Modify,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        dir.SetAccessControl(security);
        var file = Path.Combine(dir.FullName, "fake.exe");
        File.WriteAllText(file, "x");
        var problems = SafeLocation.FindProblems(file, Self);
        Assert.True(problems.Any(p => p.Contains(dir.FullName, StringComparison.OrdinalIgnoreCase) &&
                                      p.Contains(@"BUILTIN\Users", StringComparison.OrdinalIgnoreCase)),
            string.Join(" | ", problems));
    }

    [Test]
    public void ObjectCheckRejectsUntrustedOwnerAndWriteAces()
    {
        var trusted = SafeLocation.TrustedSids(Self);

        var ok = new DirectorySecurity();
        ok.SetOwner(Admins);
        ok.AddAccessRule(new FileSystemAccessRule(Users, FileSystemRights.ReadAndExecute, AccessControlType.Allow));
        ok.AddAccessRule(new FileSystemAccessRule(Self, FileSystemRights.FullControl, AccessControlType.Allow));
        // Inherit-only ACEs (CREATOR OWNER in Program Files) do not apply to the object itself.
        ok.AddAccessRule(new FileSystemAccessRule(Stranger, FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit, PropagationFlags.InheritOnly, AccessControlType.Allow));
        Assert.Equal(0, Problems(ok, SafeLocation.DirectoryWrite, trusted).Count, "tight ACL");

        var owned = new DirectorySecurity();
        owned.SetOwner(Stranger);
        Assert.Contains("owned by", Problems(owned, SafeLocation.AncestorWrite, trusted).Single());

        var plantable = new DirectorySecurity();
        plantable.SetOwner(Admins);
        plantable.AddAccessRule(new FileSystemAccessRule(Users, FileSystemRights.CreateFiles, AccessControlType.Allow));
        Assert.Equal(1, Problems(plantable, SafeLocation.DirectoryWrite, trusted).Count, "AddFile on the exe's folder");
        Assert.Equal(0, Problems(plantable, SafeLocation.AncestorWrite, trusted).Count, "AddFile on an ancestor (like C:\\)");

        var renamable = new DirectorySecurity();
        renamable.SetOwner(Admins);
        renamable.AddAccessRule(new FileSystemAccessRule(Users, FileSystemRights.Delete, AccessControlType.Allow));
        Assert.Equal(1, Problems(renamable, SafeLocation.AncestorWrite, trusted).Count, "Delete on an ancestor");

        Assert.True((SafeLocation.Expand((FileSystemRights)0x40000000) & FileSystemRights.WriteData) != 0, "GENERIC_WRITE");
        Assert.True((SafeLocation.Expand((FileSystemRights)0x10000000) & FileSystemRights.ChangePermissions) != 0, "GENERIC_ALL");
    }

    private static List<string> Problems(FileSystemSecurity security, FileSystemRights forbidden, IReadOnlySet<SecurityIdentifier> trusted)
    {
        var problems = new List<string>();
        SafeLocation.CheckObject(security, "X", forbidden, trusted, problems);
        return problems;
    }

    [Test]
    public void LogonTaskRunsHeadlessServeInTheUsersSession()
    {
        var xml = HostCommands.BuildTaskXml(@"C:\Program Files\wsb-mcp\wsb-mcp.exe", @"PC\alice");
        var doc = XDocument.Parse(xml);
        XNamespace ns = "http://schemas.microsoft.com/windows/2004/02/mit/task";
        var exec = doc.Descendants(ns + "Exec").Single();
        Assert.True(exec.Element(ns + "Command")!.Value.EndsWith(@"\conhost.exe", StringComparison.OrdinalIgnoreCase), "conhost");
        Assert.Equal("--headless \"C:\\Program Files\\wsb-mcp\\wsb-mcp.exe\" serve", exec.Element(ns + "Arguments")!.Value);
        Assert.Equal(@"PC\alice", doc.Descendants(ns + "LogonTrigger").Single().Element(ns + "UserId")!.Value);
        var principal = doc.Descendants(ns + "Principal").Single();
        Assert.Equal("InteractiveToken", principal.Element(ns + "LogonType")!.Value);
        Assert.Equal("LeastPrivilege", principal.Element(ns + "RunLevel")!.Value);
        Assert.Equal("PT0S", doc.Descendants(ns + "ExecutionTimeLimit").Single().Value);
    }

    [Test]
    public void ClaudeSideInstructionsMatchThePipe()
    {
        var standard = string.Join('\n', HostCommands.ClaudeSideInstructions("A", @"C:\x\wsb-mcp.exe", "wsb-mcp"));
        Assert.Contains("/plugin install", standard);
        Assert.Contains("\"C:\\x\\wsb-mcp.exe\" proxy", standard);
        Assert.True(!standard.Contains("--pipe", StringComparison.Ordinal), standard);

        var custom = string.Join('\n', HostCommands.ClaudeSideInstructions("A", @"C:\x\wsb-mcp.exe", "lab"));
        Assert.Contains("proxy --pipe lab", custom);
        Assert.True(!custom.Contains("/plugin install", StringComparison.Ordinal), "plugin would use the default pipe");
    }

    [Test]
    public void StopSignalRefusesASecondOwnerAndCanBeSignaled()
    {
        var pipe = "wsb-mcp-test-" + Guid.NewGuid().ToString("N");
        Assert.True(!StopSignal.TrySignal(pipe), "nothing to signal yet");
        using var signal = StopSignal.Create(pipe);
        Assert.Contains("Refusing to start", Assert.Throws<InvalidOperationException>(() => StopSignal.Create(pipe)).Message);
        Assert.True(StopSignal.TrySignal(pipe), "signaled");
        Assert.True(signal.WaitOne(TimeSpan.FromSeconds(5)), "event set");
    }

    [Test]
    public async Task RecoveryStopsOnlyTheRecordedGuest()
    {
        var root = _work.Dir("root");
        var id = Guid.NewGuid().ToString();

        // Recorded guest still running: stopped, record cleared.
        var wsb = new ScriptedWsb { Id = id, Running = true };
        var record = new MemoryGuestRecord { Value = id };
        await Manager(wsb, root, record).RecoverAsync(CancellationToken.None);
        Assert.Equal(id, wsb.CallsOf("stop").Single()[2], "stopped the recorded id");
        Assert.Equal(null, record.Value, "record cleared");

        // Some other sandbox running: never touched.
        wsb = new ScriptedWsb { Id = Guid.NewGuid().ToString(), Running = true };
        record = new MemoryGuestRecord { Value = id };
        await Manager(wsb, root, record).RecoverAsync(CancellationToken.None);
        Assert.Equal(0, wsb.CallsOf("stop").Count(), "foreign sandbox untouched");
        Assert.Equal(null, record.Value, "stale record cleared");

        // Garbage in the record: ignored and cleared, wsb not even asked.
        wsb = new ScriptedWsb();
        record = new MemoryGuestRecord { Value = "--id x" };
        await Manager(wsb, root, record).RecoverAsync(CancellationToken.None);
        Assert.Equal(0, wsb.Calls.Count, "no wsb call");
        Assert.Equal(null, record.Value, "invalid record cleared");
    }

    [Test]
    public async Task GuestIdIsRecordedWhileRunningAndClearedOnStop()
    {
        var root = _work.Dir("root");
        var id = Guid.NewGuid().ToString();
        var wsb = new ScriptedWsb { Id = id };
        var record = new MemoryGuestRecord();
        var manager = Manager(wsb, root, record);
        await manager.StartAsync(null, null, new SelfClient(), CancellationToken.None);
        Assert.Equal(id, record.Value, "recorded");
        await manager.StopAsync("test", CancellationToken.None);
        Assert.Equal(null, record.Value, "cleared");
    }

    [Test]
    public async Task GuestIsStoppedIfItCannotBeRecorded()
    {
        var wsb = new ScriptedWsb { Id = Guid.NewGuid().ToString() };
        var manager = Manager(wsb, _work.Dir("root"), new FailingGuestRecord());
        await Assert.ThrowsAsync<IOException>(() => manager.StartAsync(null, null, new SelfClient(), CancellationToken.None));
        Assert.Equal(1, wsb.CallsOf("stop").Count(), "stopped instead of left untracked");
        Assert.True(!manager.IsRunning, "not running");
    }

    private sealed class FailingGuestRecord : IGuestRecord
    {
        public string? Read() => null;

        public void Write(string id) => throw new IOException("disk full");

        public void Clear()
        {
        }
    }

    private static SandboxManager Manager(ScriptedWsb wsb, string root, IGuestRecord record) =>
        new(wsb, new PathValidator(root), Fixtures.FastOptions, NullBrokerLog.Instance, TimeProvider.System, record);

    [Test]
    public void ProcessProxyWithoutBrokerAnswersWithTheHint()
    {
        using var process = Process.Start(new ProcessStartInfo(Fixtures.WsbMcpExe)
        {
            ArgumentList = { "proxy", "--pipe", "wsb-mcp-test-" + Guid.NewGuid().ToString("N") },
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            UseShellExecute = false,
        })!;
        process.StandardInput.NewLine = "\n";
        process.StandardInput.WriteLine("""{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}""");
        process.StandardInput.WriteLine("""{"jsonrpc":"2.0","id":2,"method":"tools/list"}""");
        process.StandardInput.WriteLine("""{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"sandbox_status","arguments":{}}}""");
        process.StandardInput.Close();
        var lines = process.StandardOutput.ReadToEnd().Split('\n', StringSplitOptions.RemoveEmptyEntries);
        Assert.True(process.WaitForExit(10_000), "proxy exits after EOF");
        Assert.Equal(3, lines.Length, string.Join(" | ", lines));
        Assert.Contains("\"serverInfo\"", lines[0]);
        Assert.Contains("sandbox_exec", lines[1]);
        Assert.Contains("wsb-mcp start", lines[2]);
    }

    [Test]
    public void ProcessVersionMatchesTheAssembly()
    {
        using var process = Process.Start(new ProcessStartInfo(Fixtures.WsbMcpExe)
        {
            ArgumentList = { "--version" },
            RedirectStandardOutput = true,
            UseShellExecute = false,
        })!;
        var version = process.StandardOutput.ReadToEnd().Trim();
        process.WaitForExit();
        var expected = typeof(ToolCatalog).Assembly.GetName().Version!.ToString(3);
        Assert.True(version == expected || version.StartsWith(expected + "-", StringComparison.Ordinal), version);
    }

    [Test]
    public void ProcessServeRefusesToRunFromAnAgentWritableFolder()
    {
        using var process = Process.Start(new ProcessStartInfo(Fixtures.WsbMcpExe)
        {
            ArgumentList = { "serve", "--config", Path.Combine(_work.Root, "missing.json") },
            RedirectStandardError = true,
            UseShellExecute = false,
        })!;
        var error = process.StandardError.ReadToEnd();
        process.WaitForExit();
        Assert.Equal(1, process.ExitCode, error);
        // Here (below C:\AgentSandbox) the location is unsafe. A CI checkout may be safe; then serve
        // gets past the location check and fails on the missing config instead.
        var unsafeLocation = SafeLocation.FindProblems(Fixtures.WsbMcpExe, Self).Count > 0;
        Assert.Contains(unsafeLocation ? "refusing to serve" : "missing.json", error);
    }
}
