<!-- SPDX-FileCopyrightText: 2026 Florian Mücke
SPDX-License-Identifier: MIT
https://github.com/fmuecke/windows-sandbox-mcp -->

# Security policy

This project is a privilege bridge. The broker (`wsb-mcp serve`) runs as the
interactive user and acts on requests from a deliberately less trusted agent
account. Weaknesses in that boundary are the main thing to report.

## Reporting a vulnerability

Please **do not open a public issue**. Report privately through GitHub:
**Security → Report a vulnerability** on this repository. Include steps to
reproduce, the Windows build, and the commit you tested.

You will get a reply when the report has been looked at. This is a spare-time
project without a guaranteed response time.

## In scope

Anything that lets the agent account, or another local account, do one of the
following through the broker:

- run code or start processes as the broker user on the host;
- read, write or map host folders outside `allowedRoot`, or folders it cannot
  access itself (folder rules 1–5 in [SPEC.md](SPEC.md));
- change the guest configuration, such as enabling networking, or pass
  arguments that `wsb.exe` interprets differently than intended;
- connect to the broker pipe without being the configured agent account, or
  from the network;
- keep a guest running after the broker said it was stopped, or after the
  broker exited.

## Out of scope

- Anything the guest can do **inside** the sandbox. Commands run elevated
  there by design.
- Escapes from Windows Sandbox or Hyper-V themselves. Report those to
  Microsoft (MSRC).
- Setups that contradict the README, for example running the broker from an
  agent-writable folder or elevated.
- The limits listed under "Out of scope (v1)" in [SPEC.md](SPEC.md).

## Supported versions

Only the latest release and `master` get fixes.

Releases are self-contained: they bundle the .NET runtime, so Microsoft
Update does **not** patch it. When .NET publishes a security update, a patch
release with the updated runtime follows; Dependabot proposes the SDK update.
Keep wsb-mcp current (`winget upgrade fmuecke.WsbMcp`) to receive these fixes.
