<!-- SPDX-FileCopyrightText: 2026 Florian Mücke
SPDX-License-Identifier: MIT
https://github.com/fmuecke/windows-sandbox-mcp -->

# wsb-mcp — Specification (draft v0.1)

## Purpose

A restricted agent (OS user `AgentSandbox`) cannot start Windows Sandbox. wsb-mcp
lets it run risky commands in a fresh, offline Windows Sandbox guest and exchange
files with it — without granting any other host access.

**Success:** the agent can start a guest, map an input and an output folder, run
commands, inspect files the guest wrote, and stop the guest; no tool call lets it
reach host resources it could not already reach as `AgentSandbox`.

## Trust model

| Component | Runs as | Trust |
|-----------|---------|-------|
| Broker (`wsb-mcp serve`) | Interactive user able to run `wsb.exe` | Trusted |
| Proxy (`wsb-mcp proxy`) | `AgentSandbox`, launched by the agent host via stdio | Untrusted |
| Guest | Windows Sandbox VM | Untrusted, disposable |

The broker is a privilege bridge. Every tool argument is attacker-controlled.
The broker must never perform an action on behalf of the client that the client
could not perform itself, except starting/stopping/exec-ing the one guest it owns.

## Architecture

```
Agent host ──stdio(MCP)──> wsb-mcp proxy ──named pipe──> wsb-mcp serve ──> wsb.exe
            (AgentSandbox)                 (ACL: AgentSandbox)  (real user)
```

- Single C# executable (.NET 10, no third-party dependencies), two modes:
  - `serve`: hosts the MCP server on a named pipe.
  - `proxy`: byte-forwards stdin/stdout ↔ the pipe. No logic, no parsing.
- MCP is implemented directly (JSON-RPC 2.0, newline-delimited JSON; `initialize`,
  `ping`, `tools/list`, `tools/call`; protocol versions 2025-06-18, 2025-03-26,
  2024-11-05). The official SDK was not available offline, and the subset is
  small; zero dependencies also keeps the trusted broker's supply chain empty.
  Messages are limited to 1 MiB; an oversized message drops the client.
- Started manually in v1 (`wsb-mcp serve --config <file>`). Scheduled task /
  service later; nothing in the design may depend on an interactive console.

### Pipe security

- Pipe name fixed in broker config (default `\\.\pipe\wsb-mcp`).
- Pipe ACL: full control for broker user; read/write for the configured agent
  account SID only. No `Everyone`, no `Authenticated Users`, deny network logons.
- `FILE_FLAG_FIRST_PIPE_INSTANCE` so another process cannot squat the name.
- On connect, the broker verifies the client token SID equals the configured
  agent SID (defence in depth beyond the ACL); otherwise disconnect.
- One client connection at a time. The single pipe instance is reused
  (disconnect + wait) so there is no window in which the name can be squatted.
- The proxy connects with `Identification` level; `Anonymous` is rejected. A
  non-elevated broker (no `SeImpersonatePrivilege`) receives at most an
  Identification-level token for another account anyway, so it can identify the
  client and run access checks for it (rule 4) but never act as it.

## Broker configuration (host-only, never exposed via tools)

| Key | Example | Meaning |
|-----|---------|---------|
| `agentAccount` | `AgentSandbox` | Only account allowed to connect |
| `allowedRoot` | `C:\AgentSandbox` | All mapped folders must be below this |
| `pipeName` | `wsb-mcp` | Named pipe name |
| `idleTimeoutMinutes` | `30` | Stop guest after no tool call for this long |
| `maxExecTimeoutSeconds` | `1800` | Upper bound for `sandbox_exec` timeout |
| `startupTimeoutSeconds` | `120` | Wait for guest readiness (share retry) |
| `logPath` | `%LOCALAPPDATA%\wsb-mcp\broker.log` | JSON-lines log |
| `wsbPath` | `wsb.exe` | wsb executable (override for tests) |

Unknown keys are rejected. The broker refuses to start if its executable, the
config file or the log directory is inside `allowedRoot` (agent-writable), or if
`agentAccount` is the broker's own account.

## Hard-coded guest configuration

Passed to `wsb start` as a fixed config; no tool parameter can alter it.

- Networking: **Disable**
- vGPU: Disable
- Clipboard redirection: Disable
- Audio input: Disable
- Video input: Disable
- Printer redirection: Disable
- Protected client: Enable
- No logon command, no config-level mapped folders (mapping is done via
  `wsb share` after path validation).

## Folder mapping rules

Guest paths are fixed: input → `C:\SandboxIn` (read-only), output →
`C:\SandboxOut` (writable). If input and output resolve to the same directory,
only one writable mapping is made at `C:\SandboxOut` (and `C:\SandboxIn` is absent).

Validation, performed for each host path, in this order:

1. Must be absolute, local (no UNC, no `\\?\GLOBALROOT`, no device paths), and an
   existing directory.
2. Open the directory handle (`FILE_FLAG_BACKUP_SEMANTICS`, **no**
   `FILE_SHARE_DELETE`) and obtain the final path via `GetFinalPathNameByHandle`.
   This resolves junctions/symlinks/8.3 names. The handle must include a data
   right (`FILE_LIST_DIRECTORY`): attribute-only handles do not take part in
   share-mode checks and do not block rename/delete (verified by test). If the
   normalized name is not available (no list access on an ancestor), the opened
   name is used; it may keep 8.3 components, which can only cause rejections.
3. Final path must be equal to or below the final path of `allowedRoot`
   (case-insensitive, separator-aware prefix comparison).
4. Check the **pipe client's** access: `AccessCheck` with the client's
   Identification token against the security descriptor (owner, group, DACL,
   integrity label) read from the rule 2 handle (`READ_CONTROL`): list+read
   attributes for input; additionally add-file+add-subdirectory for output.
   Only the directory itself is checked (traverse checking is bypassed for
   standard accounts).
5. Keep the handle open until `wsb share` returned, so the directory cannot be
   swapped for a junction between check and share (TOCTOU).

Any failure → tool error naming the rule that failed; no guest state changes.

### Links inside a mapped folder (validated 2026-11-01)

The rules above pin only the mapped directory itself. The agent can create
junctions inside a writable mapped folder at any time (no privilege needed;
directory/file symlinks need a privilege that neither the agent nor the broker
user had). Probed with junctions created before and after the share, pointing at
a host directory readable only by the broker user:

- The guest sees the junction as a reparse point and **resolves its target in
  the guest namespace**. The host never follows it: with a decoy at the same
  path inside the guest, the guest read the decoy, and writes went to the guest
  copy; the host directory was unchanged.
- Without a decoy the target simply does not exist in the guest
  ("Could not find a part of the path"), for both System and the session user.
- `wsb share` does not modify the ACL of the shared folder.

Conclusion: links inside a mapped folder cannot leak or change host data through
the guest. The broker itself never traverses the contents of mapped folders.
### Arguments passed to wsb.exe

All arguments go through an argv list (no shell). Agent-supplied guest strings
(`command`, `workingDirectory`) must be non-empty, ≤ 8000 chars, contain no NUL,
and must not start with `-` (option injection) or `@` (wsb's command-line parser
would read a response file **on the host** as the broker user).

## Tools

All tools return structured JSON. Errors are MCP tool errors with a message.

### `sandbox_start`

| Param | Type | Required |
|-------|------|----------|
| `inputPath` | string | no |
| `outputPath` | string | no |

- Refuses if any Windows Sandbox is running (`wsb list` non-empty), including one
  the user opened manually.
- Validates paths (see above) **before** starting the guest.
- Starts guest, retries `wsb share` until ready or `startupTimeoutSeconds`.
- On any failure after start: stops the guest before returning the error.
- Returns `{ id, inputGuestPath?, outputGuestPath?, startupSeconds }`.

### `sandbox_exec`

| Param | Type | Required | Default |
|-------|------|----------|---------|
| `command` | string | yes | |
| `workingDirectory` | string (guest path) | no | output guest path, else `C:\` |
| `runAs` | `system` \| `user` | no | `system` |
| `timeoutSeconds` | int | no | `maxExecTimeoutSeconds` |

- Requires a running guest owned by this broker.
- Runs `wsb --raw exec --id <id> -d <dir> -r <System|ExistingLogin> -c <command>`.
  `system` → `System` (`NT AUTHORITY\SYSTEM`); `user` → `ExistingLogin`
  (`WDAGUtilityAccount`, elevated), with the lazy `wsb connect` from Q7.
  Both are elevated.
- Returns `{ exitCode, durationSeconds, timedOut }`. `exitCode` is the guest
  process exit code parsed from `wsb --raw exec` JSON (`ExitCode`), not the
  `wsb.exe` exit code. A nonzero `wsb.exe` exit (launch failure) is a tool error
  carrying the `wsb` message.
- On timeout the broker kills its `wsb.exe exec` client process; the guest
  process is unaffected.
- `wsb exec` does not return guest stdout/stderr. The agent redirects output to
  files under the output mapping itself (e.g.
  `cmd /c mytest.exe > C:\SandboxOut\log.txt 2>&1`) and reads them on the host.

### `sandbox_status`

No params. Returns `{ running, id?, startedAt?, lastActivityAt?, inputHostPath?,
outputHostPath? }`.

### `sandbox_stop`

No params. Stops the owned guest; idempotent (no guest → success, `stopped: false`).
Returns `{ stopped, totalSeconds }`.

## Lifecycle guarantees

- At most one guest, owned by the broker.
- Guest is stopped on: `sandbox_stop`, idle timeout, client (proxy) disconnect,
  broker shutdown (Ctrl+C / SIGTERM / service stop), and unhandled broker error.
- Broker never stops a guest it did not start.

## Logging

Broker logs every tool call (tool, arguments, result, duration) to a host-only
log file outside `allowedRoot`, so the agent cannot tamper with it.

## Setup and distribution (v1.1)

Goal: three steps from nothing to working tools, each run by the right account:

1. As admin: `winget install fmuecke.WsbMcp` (machine scope).
2. As you: `wsb-mcp setup --agent AgentSandbox --root C:\AgentSandbox`.
3. As the agent, in Claude Code: `/plugin marketplace add fmuecke/windows-sandbox-mcp`
   and `/plugin install wsb-mcp@windows-sandbox-mcp`. Alternatively, run
   `claude mcp add` with the command that `setup` prints.

### Commands

| Command | Run as | Does |
|---|---|---|
| `serve [--config <path>]` | you | As now; the config defaults to `%LOCALAPPDATA%\wsb-mcp\config.json`. |
| `setup --agent <account> --root <dir> [--pipe <name>] [--no-autostart] [--force]` | you, **not elevated** | Preflight checks, then writes the config, registers and starts the logon task, waits for the pipe and prints the Claude-side steps. It refuses an existing config without `--force`. |
| `start` / `stop` | you | Start the logon task now / stop the broker gracefully. The broker stops the guest first, and `stop` waits up to 60 s. |
| `uninstall [--keep-config]` | you | `stop`, then delete the task, the config and the log. The program itself is removed with `winget uninstall`. |
| `diag` | you or the agent | Checks each link of the chain and prints OK/FAIL with a fix for each. Exits 1 if anything fails. |
| `proxy [--pipe <name>]` | the agent (MCP host) | See "Proxy" below. |

`setup` refuses to run elevated. The task and config must belong to the
interactive user. With over-the-shoulder elevation, an elevated shell is a
different account.

Preflight checks done by `setup` and `diag`:
- `wsb --version` works. If not, they print the `Enable-WindowsOptionalFeature`
  command.
- The executable is in a **safe location** (rule below).
- The agent account exists and differs from the current user.
- `--root` exists, and the exe and config are outside it.
- The agent can probably run the exe: the exe's DACL grants read and execute
  to the agent SID or to a group such as Users. This is a warning only;
  `diag` run as the agent checks it for real.

### Safe-location rule (new, enforced by `serve` and `setup`)

"Trusted" below means SYSTEM, Administrators, TrustedInstaller or the broker
user. The **owner** of every object checked must be trusted, because an owner
can always rewrite the DACL; a folder the agent created is therefore rejected
even with a tight DACL. Inherit-only ACEs (for example `CREATOR OWNER` in
Program Files) are ignored, because they don't apply to the object itself.
Deny ACEs are not subtracted, which can only cause false rejections. These ACL
entries must not grant any other SID the rights listed:

- **The resolved executable file:** `WriteData`, `AppendData`,
  `WriteExtendedAttributes`, `WriteAttributes`, `Delete`, `WriteDAC`,
  `WriteOwner`.
- **Its directory:** `AddFile` and `AddSubdirectory` (DLL planting next to
  the exe), plus `DeleteChild`, `Delete`, `WriteDAC` and `WriteOwner`.
- **Every ancestor up to the volume root:** `Delete`, `DeleteChild`,
  `WriteDAC` and `WriteOwner`. Any of these would let a folder on the path be
  renamed, replaced or re-permissioned. `AddFile` and `AddSubdirectory` are
  allowed here, because `C:\` grants *Authenticated Users* the right to create
  folders. A new folder can't affect an existing path. This replaces "exe not inside allowedRoot" for the exe, and
also catches a hand-made `C:\Tools` folder that inherits the `C:\` ACL.
`C:\Program Files\…` and `C:\Program Files\WinGet\Packages\…` pass by default.

### Logon task

- **Task:** `\wsb-mcp\broker`, for the current user. Trigger: logon of that
  user. Principal: `InteractiveToken`, `LeastPrivilege`.
- **Settings:** no time limit; ignore a new instance while one is running;
  also runs on battery. Restart-on-failure (3× at 1-minute intervals) only
  covers a failed *launch*. Task Scheduler does not restart a process that
  exits with an error. A crashed broker comes back at the next logon or with
  `wsb-mcp start`, and `diag` reports it as not running.
- **Action:** `conhost.exe --headless "<resolved exe>" serve`, so no console
  or Terminal window appears. The log is `broker.log`.
- **Graceful stop:** the broker waits on a named event
  `Local\wsb-mcp-<pipe>-stop`, whose ACL allows only the broker user and
  SYSTEM. `stop` signals the event; the broker then treats it like Ctrl+C,
  and `stop` waits until the pipe is gone. `Local\` is the logon session's
  namespace. An agent running in the same session could create the event
  first, so the broker **refuses to start** if the event already exists,
  rather than use an event someone else controls. The worst case is a denial
  of service. Ending the task kills the process without stopping the guest,
  so `stop` is the only documented way.
- **Crash recovery:** the broker records the id of the guest it started in
  `%LOCALAPPDATA%\wsb-mcp\guest.id` and deletes the file when the guest is
  stopped. At startup, if the recorded id is still in `wsb list`, it stops
  that guest. That is still a guest it started itself, so the rule in
  "Lifecycle guarantees" holds.
- **Upgrade:** the running exe is locked. The documented upgrade sequence is
  `wsb-mcp stop`, then `winget upgrade`, then `wsb-mcp start`.

### Proxy

- Line-based JSON-RPC, still with no access to anything the agent can't
  reach itself. It tries to connect for 1 s.
- **Online:** it forwards lines both ways, as now.
- **Offline** (no broker): the proxy answers `initialize`, `ping` and
  `tools/list` itself, with the same tool names and schemas and generic limit
  texts. Each `tools/call` first retries the connection.
  - If the broker is now there, the proxy replays the stored `initialize` and
    `notifications/initialized`, discards the broker's reply to it, forwards
    the call and switches to online.
  - Otherwise it returns an `isError` result: "The wsb-mcp broker is not
    running. Ask the user to run `wsb-mcp start` (or `wsb-mcp setup` if it was
    never set up); `wsb-mcp diag` shows details."
- **Broker lost while online:** the proxy answers every in-flight request with
  the same error and switches to offline. The guest is stopped by the broker
  as before.

### Packaging

- **Exe:** self-contained, single-file, trimmed `wsb-mcp.exe` for win-x64 and
  win-arm64, so no .NET is needed on the machine. Config parsing moves to
  source-generated JSON, so trimming is warning-free; the trim analyzers run
  in every build.
- **Release assets:** zips for both architectures, `wsb-mcp.mcpb` (x64,
  binary server, `win32`, args `proxy`), `SHA256SUMS.txt` and provenance
  attestations.
- **MCP Registry:** `server.json` named
  `io.github.fmuecke/windows-sandbox-mcp`, with an `mcpb` package that points
  to the release asset and its SHA-256. The release workflow publishes it
  with `mcp-publisher` and GitHub OIDC.
- **winget:** `fmuecke.WsbMcp`, installer type `portable`, command
  `wsb-mcp`, `Scope: machine`. The first version goes in through a manual pull
  request to microsoft/winget-pkgs; later ones are automated (for example
  wingetcreate with a token secret).
- **Claude plugin:** `.claude-plugin/marketplace.json` at the repo root lists
  `plugins/wsb-mcp`. Its `.mcp.json` runs `wsb-mcp proxy` via PATH, which is
  fine because the proxy holds no privilege. It ships one skill, `wsb-mcp`:
  the tool workflow, folder rules, output through files, limits, and what to
  do when the offline hint appears. The `windows-sandbox-tests` skill is
  deliberately not included: its framework runs `wsb.exe` directly, which the
  restricted agent this plugin serves cannot do.

  Under `strictKnownMarketplaces`, the admin must allow this marketplace.

Every listing states: Windows 11 24H2 or later, Windows Sandbox enabled, and a
separate agent account. Without `setup`, the tools only return the offline
hint.

### Validation status (2026-11-07)

**Covered by tests** (`SetupTests`, `ProxyTests`):
- the safe-location rule, both in unit tests and against the real ACLs of
  `System32` and `Program Files`;
- `serve` refusing an unsafe location;
- the task XML;
- stop-event creation, refusal and signaling;
- crash recovery, which touches only the recorded GUID;
- the offline proxy, reconnecting and losing the broker, including through
  the exe;
- pending responses after the client's input closes.

**Validated on the real system (2026-11-07)** with the framework-dependent
build in `C:\Program Files\wsb-mcp`:
- `setup` registered the logon task, and the broker started from it through
  `conhost --headless`, with no console window;
- `diag` as the broker user: all 6 checks OK; as the agent: the broker
  accepts the account;
- `stop` and `start` against the task-started broker;
- the real smoke test through the installed exe's new proxy: 19/19.

**Not yet validated on a real system:**
- the upgrade sequence;
- the self-contained, trimmed build (CI only; NuGet is unreachable from the
  development sandbox);
- installing the plugin;
- the formats of the MCPB manifest, `server.json` and the winget manifests,
  which were written from memory. CI validates the MCPB manifest and the
  plugin; registry and winget find out on publish.

## Out of scope (v1)

- Exposing any WSB configuration to the agent.
- Networking in the guest.
- Multiple concurrent guests or clients.
- Capturing guest stdout/stderr by the broker.
- Non-elevated (standard user) execution. Both `runAs` values are elevated; an
  agent that needs a standard user creates one in the guest itself.

## v2 backlog (test convenience)

- Copy/staging of input (psm1 pattern) for tests that must not touch originals.
- Standard-user `runAs`.
- Provisioning helpers, e.g. copying VC++ debug runtime (vcredist debug) DLLs
  into the guest, mapping a host PowerShell 7 installation read-only.

## Decisions

- **Q1** Agent sandbox → broker named pipe connectivity: **validated
  2026-11-01** (throwaway probe). The restricted agent opened a pipe created by the real
  user, with an ACL allowing only the broker user and the agent SID and denying
  network logons. The broker identified the client as `AgentSandbox` and
  impersonated it successfully. **Correction (first real run, 2026-11-01):** the
  probe did not check the token level. The non-elevated broker only gets an
  `Identification` token, so opening files as the client is impossible; rule 4
  uses `AccessCheck` instead and the proxy requests only `Identification`.
- **Q2** Exec timeout: report only (`timedOut: true`); guest keeps running.
- **Q3** Proxy disconnect stops the guest. (Narrowest choice; may be relaxed later.)
- **Q4** Broker does not capture stdout/stderr; the agent redirects to files.
- **Q7** `runAs: user` is supported via a lazily created session. On the first
  `user` exec, the broker runs `wsb connect` (opens a visible sandbox window on
  the host desktop), then retries `ExistingLogin` until the session exists.
  **Validated 2026-11-01** (throwaway probe). Consequence: the
  broker must run in an interactive desktop session; a session-0 service cannot
  offer `runAs: user`.
  Algorithm: run `ExistingLogin` exec; on `0x80070520` run `wsb connect`
  (returns immediately) and retry every 2 s up to 60 s. Same path recovers if
  the user closed the sandbox window.
  Note: `user` is `WDAGUtilityAccount`, a local admin at **High** integrity
  (effectively elevated). Neither `runAs` value gives a standard-user token.

## Observed wsb behaviour (probe run 2026-11-01, ProtectedClient enabled)

- `wsb --raw start --config "<Configuration>…</Configuration>"` accepts the
  hard-coded config inline and returns `{"Id": "<guid>"}` (~1.6 s).
- `wsb --raw list` returns `{"WindowsSandboxEnvironments": [{"Id": …}]}`.
- `share` without `-w` is read-only in the guest (write → access denied);
  with `-w` it is writable. Both succeeded on the first attempt after start.
- Networking disabled: guest has only the loopback IPv4 address; DNS and
  outbound TCP fail.
- **`wsb exec` always exits 0 if it launched the process. The guest exit code is
  only in the JSON output: `{"ExitCode": 7}`.** The broker must parse it.
  (WindowsSandboxTest 1.0.0 checked only the `wsb` exit code and missed guest
  failures; fixed in 1.1.0.)
- `wsb exec` waits for the guest process to finish and returns no guest
  stdout/stderr.
- `-r ExistingLogin` fails with `0x80070520` (no logon session) when no user
  session is active in the guest. `System` works.
- `wsb connect --id` returns within ~1 s (exit 0) and opens the sandbox window;
  the user session is usable ~4 s later. A second `connect` also exits 0.
  Connect client processes do not outlive `wsb stop`.
- Session user: `WDAGUtilityAccount`, member of `Administrators`, High
  mandatory level, `net session` succeeds.

## Validation plan (cheapest first)

1. ~~From agent sandbox: open a named pipe created by the real user with the
   described ACL. (Q1)~~ Passed.
2. ~~`wsb start --config <hardened xml>` → no network in guest.~~ Passed.
3. ~~`wsb share` without `-w` → guest write to `C:\SandboxIn` fails.~~ Passed.
4. ~~Path rules: junction under root pointing outside → rejected; path not
   readable by `AgentSandbox` → rejected~~ (passed in the real run);
   swap attempt during share → blocked (unit test only).
5. Pipe: connection from a different user → rejected. Pipe ACL and SID check
   are in place; only anonymous rejection is tested.
6. Lifecycle: ~~proxy disconnect → guest gone~~ (passed in the real run);
   ~~Ctrl+C broker → guest gone~~ (passed; `wsb list` empty afterwards);
   idle timeout (unit test only).
7. ~~Junction inside a writable mapped folder pointing to a directory readable by
   the broker user but not by the agent → the guest must not be able to list it.~~
   Passed (links are resolved in the guest).

**Real run 2026-11-01** (`tests/smoke/real-smoke.ps1 -HoldForCtrlC`, broker
published from `bd235d8` as the interactive user, proxy as `AgentSandbox`):
21/21 checks passed. These were rules 1–4 across accounts, mapping
input/output, input read-only, no network, guest exit code, `runAs: user`
with lazy connect, exec timeout, `@` rejection, status, stop, stop on
disconnect, and proxy ending on broker Ctrl+C. Afterwards `wsb list` on the
host was empty. `tests/WsbMcp.Tests` covers
the remaining items against a fake `wsb.exe`.
