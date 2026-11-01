<!-- SPDX-FileCopyrightText: 2026 Florian Mücke
SPDX-License-Identifier: MIT
https://github.com/fmuecke/windows-sandbox-mcp -->

# wsb-mcp

MCP server that lets a restricted agent run risky commands in a fresh, offline
Windows Sandbox guest, without access to anything else on the host.
Design and validated `wsb.exe` behaviour: [SPEC.md](SPEC.md).

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

Every step below runs as you unless it says otherwise.

### Prerequisites

- **Windows Sandbox with the `wsb` command-line tool** (Windows 11 24H2 or
  later; virtualization enabled in firmware). To enable it, run this as admin
  and reboot:
  ```powershell
  Enable-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM -All
  ```
  Check: `wsb --version` works in your terminal.
- **.NET 10 SDK** to build. The published build is framework-dependent, so
  the agent account also needs the .NET 10 runtime. A machine-wide install
  covers both.
- **git**.

### Steps

The broker runs with your rights. Anything the agent can write must not
influence it, so the broker **refuses to start** if its executable, its
config file or its log directory is inside `allowedRoot`.

1. Build from a reviewed commit in a clone the agent cannot modify. Publish
   to a folder only you can write but the agent can execute; the proxy runs
   from there too:
   ```powershell
   $src = "$env:LOCALAPPDATA\wsb-mcp\src"
   git -c safe.directory=C:/AgentSandbox/wsb-mcp clone --no-local C:\AgentSandbox\wsb-mcp $src   # once
   git -C $src fetch origin
   git -C $src checkout --detach <reviewed-commit>

   $dir = 'C:\Tools\wsb-mcp'
   New-Item -ItemType Directory $dir -Force | Out-Null
   icacls $dir /inheritance:r /grant:r "${env:USERNAME}:(OI)(CI)F" "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" "AgentSandbox:(OI)(CI)RX"
   dotnet publish "$src\src\WsbMcp" -c Release -o $dir
   ```
   Do not build from `C:\AgentSandbox` directly: it is writable by the agent
   (and by *Authenticated Users*).
2. Create `%LOCALAPPDATA%\wsb-mcp\config.json`:
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
   Only `agentAccount` and `allowedRoot` are required. Unknown keys are rejected.
   Optional `wsbPath` overrides `wsb.exe` (for testing).
3. Start the broker in your interactive session (needed for `runAs: user`):
   ```powershell
   & C:\Tools\wsb-mcp\wsb-mcp.exe serve --config "$env:LOCALAPPDATA\wsb-mcp\config.json"
   ```
   It logs `broker.listening` and waits. Ctrl+C stops the broker and the
   guest. The broker must run in your interactive desktop session, because
   `runAs: user` opens a sandbox window. A session-0 service cannot do that.
4. Register the proxy with the agent's Claude Code. Use the variant that
   matches how the agent account is managed:
   - **Unmanaged agent account.** Register it in the agent account's user
     scope. Run as the agent account:
     ```powershell
     claude mcp add --scope user wsb -- C:\Tools\wsb-mcp\wsb-mcp.exe proxy
     ```
   - **Agent account governed by managed settings.** Use this variant when
     `C:\Program Files\ClaudeCode\managed-settings.json` exists. Policies
     such as `strictPluginOnlyCustomization: ["mcp"]` or
     `allowManagedMcpServersOnly` make Claude Code ignore user and project
     servers. `/mcp` then shows "No MCP servers configured". Define the server
     centrally instead, as admin, in
     `C:\Program Files\ClaudeCode\managed-mcp.json`:
     ```json
     {
       "mcpServers": {
         "wsb": { "command": "C:\\Tools\\wsb-mcp\\wsb-mcp.exe", "args": ["proxy"] }
       }
     }
     ```
     If `managed-settings.json` has an `allowedMcpServers` list, add
     `{ "serverCommand": ["C:\\Tools\\wsb-mcp\\wsb-mcp.exe", "proxy"] }`
     to it.

   Avoid a project `.mcp.json` inside an agent-writable repo. If you ever
   open the repo as your own account and approve it, agent-modifiable code
   runs with your rights. The proxy runs as the agent and only forwards
   bytes, so tampering with it would gain the agent nothing. Running it from
   the protected folder still matters for three reasons:
   - No other account can swap it.
   - It is the reviewed build.
   - Rebuilding the repo does not lock or replace it while a session uses it.
5. Restart the agent's Claude Code session. `/mcp` should list `wsb` with
   four tools.

### Verify

As the agent account, with the broker running:
```powershell
pwsh -NoProfile -File tests\smoke\real-smoke.ps1 -ProxyExe C:\Tools\wsb-mcp\wsb-mcp.exe -HoldForCtrlC
```
It runs 21 checks against the real sandbox:
- folder rules
- read-only input
- no network
- exit codes
- `runAs: user`
- timeout
- stop on disconnect

At the end it asks you to press Ctrl+C in the broker window. Then
`wsb list` must show no sandbox.

### Update

Repeat step 1 with the new reviewed commit. Stop the broker first, because
it runs from the same folder. Then do steps 3 and 5.

### Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| `/mcp`: "No MCP servers configured" | Managed policy blocks user and project servers. See step 4, managed variant. |
| Proxy: "broker pipe … not available" (exit 2) | The broker is not running, or another client is connected (one at a time). |
| The broker log shows `client.rejected` | The connecting account is not `agentAccount`, or it connected anonymously. |
| The broker refuses to start: "inside allowedRoot" | The exe, config or log is in an agent-writable location. Move it. |
| Rule 4 rejects a folder you think is fine | The *agent* lacks list (input) or create-file (output) rights on that exact folder. Check with `icacls`. |
| The agent cannot start `C:\Tools\wsb-mcp\wsb-mcp.exe` | The `icacls` grant in step 1 is missing. If the short name does not resolve, use `<COMPUTERNAME>\AgentSandbox`. |

### Uninstall

Stop the broker. Remove the `wsb` registration from step 4. Then delete
`C:\Tools\wsb-mcp` and `%LOCALAPPDATA%\wsb-mcp`.

## License
MIT - Florian Mücke, 2026