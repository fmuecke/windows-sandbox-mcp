<!-- SPDX-FileCopyrightText: 2026 Florian Mücke
SPDX-License-Identifier: MIT
https://github.com/fmuecke/windows-sandbox-mcp -->

# Windows Sandbox MCP

MCP server that lets a restricted agent run risky commands in a fresh, offline
Windows Sandbox guest, without access to anything else on the host.
Design and validated `wsb.exe` behaviour: [SPEC.md](SPEC.md).
Reporting vulnerabilities: [SECURITY.md](SECURITY.md).

`wsb-mcp` is the name of the executable, the project and the solution.

```
Agent host ──stdio──> wsb-mcp proxy ──named pipe──> wsb-mcp serve ──> wsb.exe
           (agent account)        (ACL: agent only)  (your account)
```

## Tools

| Tool | Purpose |
|------|---------|
| `sandbox_start` | Start a guest; optionally map `inputPath` read-only at `C:\SandboxIn` and `outputPath` writable at `C:\SandboxOut`. |
| `sandbox_exec` | Run a command (`runAs` `system` or `user`, both elevated). Returns the guest exit code only; redirect output to files in `C:\SandboxOut`. |
| `sandbox_status` | Running state, id, mapped folders. |
| `sandbox_stop` | Stop and discard the guest. |

The guest is also stopped when the agent disconnects, after the idle timeout,
and when the broker exits.

## Build and test

```powershell
dotnet build
dotnet run --project tests/WsbMcp.Tests          # all tests, optional name filter as argument
pwsh -NoProfile -File tests/WindowsSandboxTest.Tests.ps1   # psm1 tests
```

The tests use a fake `wsb.exe` and do not need Windows Sandbox.

## Installation

Two accounts are involved:
- **You:** the interactive user, who runs the broker.
- **The agent:** for example `AgentSandbox`, which runs Claude Code and the proxy.

**Requirements:** Windows 11 24H2 or later, with Windows Sandbox enabled. To
enable it, run this as admin and reboot:
```powershell
Enable-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM -All
```
The release build is self-contained, so no .NET is needed.

### Quick start

1. **Install the program** (admin; installs below `C:\Program Files`):
   ```powershell
   winget install fmuecke.WsbMcp --scope machine
   ```
2. **Set up the broker.** Run this as **you**, in a normal terminal, not
   elevated:
   ```powershell
   wsb-mcp setup --agent AgentSandbox --root C:\AgentSandbox
   ```
   - `--root` is the folder below which the agent may map folders into the
     sandbox.
   - `setup` checks the prerequisites, writes the config, and registers a
     logon task that starts the broker hidden in your desktop session.
   - It then starts the broker and prints the next step.
3. **Connect Claude Code.** As the **agent**, in Claude Code:
   ```
   /plugin marketplace add fmuecke/windows-sandbox-mcp
   /plugin install wsb-mcp@windows-sandbox-mcp
   ```
   The plugin adds the four tools plus a skill that teaches Claude how to use
   them. Without plugins, use this instead:
   `claude mcp add --scope user wsb -- wsb-mcp proxy`.

Check everything with `wsb-mcp diag`, run as you or as the agent. If the
broker isn't running, the tools say so and tell you what to run. Once it's
running, the next call works without restarting Claude Code.

### Commands

| Command | Run as | Purpose |
|---------|--------|---------|
| `wsb-mcp setup --agent <account> --root <dir> [--pipe <name>] [--no-autostart] [--force]` | you (not elevated) | One-time setup: config, logon task, start. |
| `wsb-mcp start` / `wsb-mcp stop` | you | Start the broker now / stop it (and its guest) gracefully. |
| `wsb-mcp diag` | you or the agent | Check each link of the chain, with a fix for each failure. |
| `wsb-mcp uninstall [--keep-config]` | you | Stop, then remove the logon task, config and log. |
| `wsb-mcp serve [--config <path>]` | you | Run the broker in the foreground; Ctrl+C stops it. |
| `wsb-mcp proxy [--pipe <name>]` | the agent's MCP host | stdio bridge to the broker; you never run this yourself. |

The config is `%LOCALAPPDATA%\wsb-mcp\config.json`. `setup` writes the first
three keys; the others are optional:
```json
{
  "agentAccount": "AgentSandbox",
  "allowedRoot": "C:\\AgentSandbox",
  "pipeName": "wsb-mcp",
  "idleTimeoutMinutes": 30,
  "maxExecTimeoutSeconds": 1800,
  "startupTimeoutSeconds": 120,
  "logPath": "%LOCALAPPDATA%\\wsb-mcp\\broker.log"
}
```
Unknown keys are rejected. `wsbPath` overrides `wsb.exe`, for tests.

### Why the location matters

The broker runs with **your** rights. If anyone else could replace its exe,
they could run code as you. So `serve` and `setup` **refuse to run** if
anyone other than SYSTEM, Administrators, TrustedInstaller or you could do
one of the following:
- change the exe;
- add files next to it;
- rename or re-permission any folder on its path.

The winget install below `C:\Program Files` passes by default. The broker
also refuses a config or log inside `allowedRoot`.

### Agent accounts with managed Claude Code settings

If `C:\Program Files\ClaudeCode\managed-settings.json` restricts MCP servers,
admin changes are needed:
- `strictKnownMarketplaces`: add this repository's marketplace, for
  `/plugin marketplace add`.
- `allowedMcpServers`: add `{ "serverCommand": ["wsb-mcp", "proxy"] }`, the
  command the plugin runs.
- `strictPluginOnlyCustomization` containing `"mcp"`: only the plugin route
  works. Alternatively, define the server centrally in
  `C:\Program Files\ClaudeCode\managed-mcp.json`:
  ```json
  { "mcpServers": { "wsb": { "command": "wsb-mcp", "args": ["proxy"] } } }
  ```

Symptom of a blocking policy: `/mcp` shows "No MCP servers configured".

### Without winget

Download the zip for your architecture from the
[Releases](https://github.com/fmuecke/windows-sandbox-mcp/releases) page. CI
builds and tests it from its tag, and GitHub signs its build provenance.
Verify the zip, and extract it into a folder only admins (or you) can write:
```powershell
$zip = "$env:USERPROFILE\Downloads\wsb-mcp-<version>-win-x64.zip"
gh attestation verify $zip --repo fmuecke/windows-sandbox-mcp
$dir = "$env:ProgramFiles\wsb-mcp"            # as admin
Expand-Archive $zip -DestinationPath $dir -Force
```
Then run `& "$dir\wsb-mcp.exe" setup ...` as in step 2. For the Claude side,
`setup` prints the full exe path to use. `SHA256SUMS.txt` only detects a
damaged download. It does not prove who built the zip; the attestation does.

**From source:** build a reviewed commit in a clone the agent cannot modify,
for example with `dotnet publish src/WsbMcp -c Release -r win-x64 -o $dir`.
That needs the .NET 10 SDK and NuGet access. Never build in a checkout the
agent can write, such as one below `C:\AgentSandbox`.

### Verify against the real sandbox

As the agent account, with the broker running:
```powershell
pwsh -NoProfile -File tests\smoke\real-smoke.ps1 -ProxyExe (Get-Command wsb-mcp).Source -HoldForCtrlC
```
It runs 22 checks (19 without `-HoldForCtrlC`):
- folder rules
- read-only input
- no network
- exit codes
- `runAs: user`
- timeout
- stop on disconnect

At the end it asks you to stop the broker (`wsb-mcp stop`) and checks that the
tools then return the offline hint. Afterwards `wsb list` must show no sandbox.

### Update

Windows locks the exe while the broker runs, so stop it first:
```powershell
wsb-mcp stop
winget upgrade fmuecke.WsbMcp     # admin
wsb-mcp start
```

### Troubleshooting

Start with `wsb-mcp diag`. Common cases:

| Symptom | Cause / fix |
|---------|-------------|
| Tool error "The wsb-mcp broker is not reachable" | The broker isn't running (`wsb-mcp start`), was never set up (`wsb-mcp setup`), or another session is connected (one at a time). |
| `/mcp`: "No MCP servers configured" | A managed policy blocks the server. See "Agent accounts with managed Claude Code settings". |
| `setup` / `serve`: "not in a safe location" / "refusing to serve" | The exe is in a folder others can write to. Install with winget or below `C:\Program Files`. |
| The broker log shows `client.rejected` | The connecting account is not `agentAccount`, or it connected anonymously. |
| `serve`: "The stop event … already exists" | A broker is already running, or another process created the event. Run `wsb-mcp stop`, or sign out and back in. |
| Rule 4 rejects a folder you think is fine | The *agent* lacks list (input) or create-file (output) rights on that exact folder. Check with `icacls`. |
| `runAs: user` fails with "No user session" | The broker isn't running in your interactive desktop session. Use the logon task, not a service. |

### Uninstall

```powershell
wsb-mcp uninstall                 # as you: task, config, log
winget uninstall fmuecke.WsbMcp   # admin
```
In Claude Code, as the agent: `/plugin uninstall wsb-mcp` (or `claude mcp remove wsb`).

## License
MIT - Florian Mücke, 2026
