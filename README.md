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

## Deploy (as your own account, not the agent's)

The broker runs with your rights. Anything the agent can write must not
influence it, so the broker **refuses to start** if its executable, its
config file or its log directory is inside `allowedRoot`.

1. Publish outside the agent's reach and review what you publish:
   ```powershell
   dotnet publish src/WsbMcp -c Release -o "$env:LOCALAPPDATA\Programs\wsb-mcp"
   ```
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
   & "$env:LOCALAPPDATA\Programs\wsb-mcp\wsb-mcp.exe" serve --config "$env:LOCALAPPDATA\wsb-mcp\config.json"
   ```
   Ctrl+C stops the broker and the guest.
4. Register the proxy with the agent's MCP host, e.g. `.mcp.json`:
   ```json
   {
     "mcpServers": {
       "wsb": {
         "command": "C:\\AgentSandbox\\wsb-mcp\\src\\WsbMcp\\bin\\Debug\\net10.0-windows\\wsb-mcp.exe",
         "args": ["proxy"]
       }
     }
   }
   ```
   The proxy runs as the agent and only forwards bytes; it holds no privileges,
   so any copy the agent can execute is fine (your published copy is usually
   not readable by the agent account).
