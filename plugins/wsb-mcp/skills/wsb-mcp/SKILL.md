---
name: wsb-mcp
description: Use the wsb-mcp Windows Sandbox tools (sandbox_start, sandbox_exec, sandbox_status, sandbox_stop) to run risky, privileged or system-changing commands in a disposable offline guest instead of on the host. Covers folder mapping, getting output back, timeouts and the "broker not reachable" error.
---

# Using the Windows Sandbox tools

The tools run commands in a fresh, disposable Windows Sandbox guest with **no network**. Use
them for anything you should not run on the host: installers, registry or service changes,
admin-only tests, untrusted binaries, or machine-wide configuration.

## Workflow

1. **Prepare folders on the host** below the allowed root named in the `sandbox_start`
   description. Put inputs (scripts, binaries, test data) in one folder, and use an empty
   folder for outputs. The input folder appears read-only at `C:\SandboxIn`, and the output
   folder writable at `C:\SandboxOut`. If both are the same folder, it is mapped once,
   writable, at `C:\SandboxOut`.
2. **`sandbox_start`** with `inputPath` and/or `outputPath`. Only one guest can run at a time.
   Startup takes a few seconds.
3. **`sandbox_exec`** for each step. **Only the exit code comes back**, not stdout or stderr.
   Redirect output into the output folder, then read the file on the host:
   `cmd.exe /c C:\SandboxIn\test.cmd > C:\SandboxOut\test.log 2>&1`, or
   `powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\SandboxIn\run.ps1`, with the
   script writing its results to `C:\SandboxOut`.
4. **Read the results** from the host output folder, and judge success by the exit code and
   those files together.
5. **`sandbox_stop`** when done. The guest and everything in it is discarded. It is also
   stopped automatically when you disconnect or after a period without tool calls.

## Things to know

- **Both `runAs` values are elevated:** `system` (the default, NT AUTHORITY\SYSTEM) and
  `user` (WDAGUtilityAccount, an admin). The first `user` call opens a sandbox window on the
  user's desktop. To test as a standard user, create one inside the guest yourself.
- **No network.** Bring everything the guest needs through the input folder, including
  installers and runtimes. Windows PowerShell 5.1 is available; PowerShell 7 is not.
- **Timeouts:** pass `timeoutSeconds` for anything that might hang. On timeout the result
  has `timedOut: true` and the guest process keeps running. Stop the guest, or account for
  the process when you continue.
- **Changes on the host side are visible live** in the guest. Writes to `C:\SandboxIn` fail
  by design.
- **A command must not start with `-` or `@`.** Wrap it, for example `cmd.exe /c ...`.
- **Folder rules:** paths outside the allowed root, junctions pointing outside it, and
  folders your account cannot read (or, for output, write) are rejected. The error names
  the rule.

## "The wsb-mcp broker is not reachable"

The tools depend on a broker that the interactive user runs on the same machine. If a call
returns this error, do not retry in a loop. Tell the user which command to run in their
own (not elevated) terminal:

- `wsb-mcp start` if it was set up before (for example after a reboot or a crash);
- `wsb-mcp setup --agent <your account> --root <folder>` if it was never set up;
- `wsb-mcp diag` to see which link of the chain is broken. It works from either account.

Then call the tool again; no restart of the session is needed.
