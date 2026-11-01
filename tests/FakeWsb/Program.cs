// Fake wsb.exe mimicking `wsb --raw` behaviour observed on 2026-11-01 (see SPEC.md).
// State lives in FAKE_WSB_STATE (a directory). Every invocation's argv is appended to
// calls.jsonl there so tests can assert exact argument transport.
//   exec: exits 0 and prints {"ExitCode": n} for 'cmd.exe /c exit <n>' (else 0);
//         -r ExistingLogin fails with 0x80070520 until 'connect' was called.
using System.Text.Json;

var state = Environment.GetEnvironmentVariable("FAKE_WSB_STATE")
    ?? throw new InvalidOperationException("FAKE_WSB_STATE not set");
File.AppendAllText(Path.Combine(state, "calls.jsonl"), JsonSerializer.Serialize(args) + "\n");

var argv = args.SkipWhile(a => a == "--raw").ToArray();
string? Option(string name) { var i = Array.IndexOf(argv, name); return i >= 0 && i + 1 < argv.Length ? argv[i + 1] : null; }
var running = Path.Combine(state, "running");
var session = Path.Combine(state, "session");
const string Id = "f1ce77b0-998c-41c3-bb6f-8e246f212b33";

switch (argv.FirstOrDefault())
{
    case "list":
        Console.WriteLine(File.Exists(running)
            ? $$"""{"WindowsSandboxEnvironments": [{"Id": "{{Id}}"}]}"""
            : """{"WindowsSandboxEnvironments": []}""");
        return 0;
    case "start":
        File.WriteAllText(running, Option("--config") ?? "");
        Console.WriteLine($$"""{"Id": "{{Id}}"}""");
        return 0;
    case "share":
        return File.Exists(running) ? 0 : 1;
    case "connect":
        File.WriteAllText(session, "");
        return 0;
    case "stop":
        File.Delete(running);
        File.Delete(session);
        return 0;
    case "exec":
        var command = Option("-c") ?? "";
        if (Option("-r") == "ExistingLogin" && !File.Exists(session))
        {
            Console.WriteLine("A specified logon session does not exist. It may already have been terminated. (0x80070520)");
            return unchecked((int)0x80070520);
        }
        if (command.StartsWith("sleep ", StringComparison.Ordinal))
        {
            Thread.Sleep(int.Parse(command[6..], System.Globalization.CultureInfo.InvariantCulture) * 1000);
        }
        var exit = command.StartsWith("cmd.exe /c exit ", StringComparison.Ordinal) ? command[16..] : "0";
        Console.WriteLine($$"""{"ExitCode": {{exit}}}""");
        return 0;
    default:
        Console.WriteLine($"unknown command {argv.FirstOrDefault()}");
        return 1;
}
