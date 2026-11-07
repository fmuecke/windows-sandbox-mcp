# SPDX-FileCopyrightText: 2026 Florian Mücke
# SPDX-License-Identifier: MIT
# https://github.com/fmuecke/windows-sandbox-mcp
# Real end-to-end smoke test. Run as the AGENT account while the broker
# (`wsb-mcp serve`) runs as the broker account with a real Windows Sandbox.
# Talks MCP through `wsb-mcp proxy`, exactly like an MCP host would.
#
#   pwsh -NoProfile -File tests\smoke\real-smoke.ps1 [-HoldForCtrlC]
#
# -HoldForCtrlC: at the end, start a guest and wait until the broker is stopped with
# Ctrl+C or `wsb-mcp stop`; the tools must then return the offline hint. Afterwards verify
# on the host with `wsb list` that no sandbox is left.
param(
    [string]$ProxyExe = (Join-Path $PSScriptRoot '..\..\src\WsbMcp\bin\Debug\net10.0-windows\wsb-mcp.exe'),
    [string]$PipeName = 'wsb-mcp',
    [switch]$HoldForCtrlC
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$work = Join-Path $repo "tests\.work\smoke-$([Guid]::NewGuid().ToString('N'))"
$inDir = New-Item -ItemType Directory -Path (Join-Path $work 'in') -Force
$outDir = New-Item -ItemType Directory -Path (Join-Path $work 'out') -Force
$noAccess = New-Item -ItemType Directory -Path (Join-Path $work 'noaccess') -Force
$escape = Join-Path $work 'escape'
Set-Content -LiteralPath (Join-Path $inDir 'marker.txt') -Value 'smoke-marker-42' -NoNewline

$results = [Collections.Generic.List[object]]::new()
function Check([string]$Name, [bool]$Ok, [string]$Detail = '') {
    $results.Add([PSCustomObject]@{ Name = $Name; Ok = $Ok; Detail = $Detail })
    $color = if ($Ok) { 'Green' } else { 'Red' }
    Write-Host ("{0} {1} {2}" -f $(if ($Ok) { 'PASS' } else { 'FAIL' }), $Name, $Detail) -ForegroundColor $color
}

function Start-Proxy {
    $psi = [Diagnostics.ProcessStartInfo]::new((Resolve-Path $ProxyExe).Path)
    'proxy', '--pipe', $PipeName | ForEach-Object { $psi.ArgumentList.Add($_) }
    $psi.UseShellExecute = $false
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.StandardInputEncoding = [Text.UTF8Encoding]::new($false)
    $psi.StandardOutputEncoding = [Text.UTF8Encoding]::new($false)
    $proxy = [Diagnostics.Process]::Start($psi)
    $proxy.StandardInput.NewLine = "`n"
    $script:rpcId = 0
    $init = Invoke-Rpc $proxy 'initialize' @{ protocolVersion = '2025-06-18'; capabilities = @{}; clientInfo = @{ name = 'real-smoke'; version = '1' } }
    Invoke-Notify $proxy 'notifications/initialized'
    return [PSCustomObject]@{ Process = $proxy; Init = $init }
}

function Invoke-Notify($Proxy, [string]$Method) {
    $Proxy.StandardInput.WriteLine((@{ jsonrpc = '2.0'; method = $Method } | ConvertTo-Json -Compress))
    $Proxy.StandardInput.Flush()
}

function Invoke-Rpc($Proxy, [string]$Method, $Params, [int]$TimeoutSeconds = 300) {
    $script:rpcId++
    $request = @{ jsonrpc = '2.0'; id = $script:rpcId; method = $Method }
    if ($null -ne $Params) { $request.params = $Params }
    $Proxy.StandardInput.WriteLine(($request | ConvertTo-Json -Depth 10 -Compress))
    $Proxy.StandardInput.Flush()
    $read = $Proxy.StandardOutput.ReadLineAsync()
    if (-not $read.Wait([TimeSpan]::FromSeconds($TimeoutSeconds))) { throw "No response to $Method within $TimeoutSeconds s." }
    if ($null -eq $read.Result) { throw "Proxy closed the connection during $Method." }
    return $read.Result | ConvertFrom-Json
}

function Invoke-Tool($Proxy, [string]$Name, [hashtable]$Arguments = @{}) {
    $response = Invoke-Rpc $Proxy 'tools/call' @{ name = $Name; arguments = $Arguments }
    if ($response.PSObject.Properties['error']) { throw "JSON-RPC error: $($response.error.message)" }
    $result = $response.result
    return [PSCustomObject]@{
        IsError = [bool]$result.isError
        Text    = [string]$result.content[0].text
        Data    = if ($result.PSObject.Properties['structuredContent']) { $result.structuredContent } else { $null }
    }
}

function Stop-Proxy($Session) {
    $Session.Process.StandardInput.Close()
    if (-not $Session.Process.WaitForExit(10000)) { $Session.Process.Kill() }
}

$session = $null
try {
    # Folder the agent cannot read (the broker account still can).
    $acl = Get-Acl -LiteralPath $noAccess
    $agentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($agentSid, 'ListDirectory', 'Deny'))
    Set-Acl -LiteralPath $noAccess -AclObject $acl
    & cmd.exe /c mklink /J $escape $env:WINDIR | Out-Null

    $session = Start-Proxy
    $p = $session.Process
    Check 'initialize' ($session.Init.result.serverInfo.name -eq 'wsb-mcp') "protocol $($session.Init.result.protocolVersion)"
    $tools = (Invoke-Rpc $p 'tools/list' @{}).result.tools.name -join ','
    Check 'tools/list' ($tools -eq 'sandbox_start,sandbox_exec,sandbox_status,sandbox_stop') $tools

    $r = Invoke-Tool $p 'sandbox_start' @{ outputPath = $env:WINDIR }
    Check 'rule 3: outside root rejected' ($r.IsError -and $r.Text -match 'rule 3') $r.Text
    $r = Invoke-Tool $p 'sandbox_start' @{ outputPath = $escape }
    Check 'rule 3: junction escaping root rejected' ($r.IsError -and $r.Text -match 'rule 3') $r.Text
    $r = Invoke-Tool $p 'sandbox_start' @{ inputPath = $noAccess.FullName }
    Check 'rule 4: folder unreadable by agent rejected' ($r.IsError -and $r.Text -match 'rule 4') $r.Text

    $r = Invoke-Tool $p 'sandbox_start' @{ inputPath = $inDir.FullName; outputPath = $outDir.FullName }
    Check 'start with input+output' (-not $r.IsError) $r.Text
    if ($r.IsError) { throw 'Cannot continue without a guest.' }

    $r = Invoke-Tool $p 'sandbox_start' @{}
    Check 'second start refused' ($r.IsError -and $r.Text -match 'already running') $r.Text

    $r = Invoke-Tool $p 'sandbox_exec' @{ command = 'cmd.exe /c type C:\SandboxIn\marker.txt > C:\SandboxOut\copy.txt' }
    $copy = Join-Path $outDir 'copy.txt'
    $copied = if (Test-Path -LiteralPath $copy) { (Get-Content -LiteralPath $copy -Raw).Trim() } else { '(missing)' }
    Check 'exec reads input, writes output' ((-not $r.IsError) -and $r.Data.exitCode -eq 0 -and $copied -eq 'smoke-marker-42') "exit=$($r.Data.exitCode) copy='$copied'"

    $r = Invoke-Tool $p 'sandbox_exec' @{ command = 'cmd.exe /c exit 7' }
    Check 'guest exit code reported' ($r.Data.exitCode -eq 7) $r.Text

    $r = Invoke-Tool $p 'sandbox_exec' @{ command = 'cmd.exe /c echo x > C:\SandboxIn\written.txt' }
    Check 'input is read-only' ($r.Data.exitCode -ne 0 -and -not (Test-Path -LiteralPath (Join-Path $inDir 'written.txt'))) $r.Text

    $r = Invoke-Tool $p 'sandbox_exec' @{ command = 'ping.exe -n 1 -w 2000 1.1.1.1' }
    Check 'no network (ping fails)' ($r.Data.exitCode -ne 0) $r.Text

    $r = Invoke-Tool $p 'sandbox_exec' @{ command = 'cmd.exe /c whoami > C:\SandboxOut\whoami-user.txt'; runAs = 'user' }
    $who = Join-Path $outDir 'whoami-user.txt'
    $whoText = if (Test-Path -LiteralPath $who) { (Get-Content -LiteralPath $who -Raw).Trim() } else { '(missing)' }
    Check 'runAs user (lazy connect)' ($r.Data.exitCode -eq 0 -and $whoText -match 'wdagutilityaccount') "$($r.Text) whoami='$whoText'"

    $r = Invoke-Tool $p 'sandbox_exec' @{ command = 'ping.exe -n 30 127.0.0.1'; timeoutSeconds = 3 }
    Check 'exec timeout reported' ($r.Data.timedOut -eq $true) $r.Text

    $r = Invoke-Tool $p 'sandbox_exec' @{ command = '@C:\Windows\win.ini' }
    Check "command starting with '@' rejected" ($r.IsError) $r.Text

    $r = Invoke-Tool $p 'sandbox_status'
    Check 'status running' ($r.Data.running -eq $true -and $r.Data.outputHostPath -eq $outDir.FullName) $r.Text
    $r = Invoke-Tool $p 'sandbox_stop'
    Check 'stop' ($r.Data.stopped -eq $true) $r.Text
    $r = Invoke-Tool $p 'sandbox_status'
    Check 'status after stop' ($r.Data.running -eq $false) $r.Text

    # Disconnect stops the guest.
    $r = Invoke-Tool $p 'sandbox_start' @{}
    Check 'start without mappings' (-not $r.IsError) $r.Text
    Stop-Proxy $session
    Start-Sleep -Seconds 3
    $session = Start-Proxy
    $r = Invoke-Tool $session.Process 'sandbox_status'
    Check 'guest stopped on disconnect' ($r.Data.running -eq $false) $r.Text

    if ($HoldForCtrlC) {
        $r = Invoke-Tool $session.Process 'sandbox_start' @{}
        Check 'start before Ctrl+C' (-not $r.IsError) $r.Text
        Write-Host ''
        Write-Host 'Now stop the broker: Ctrl+C in its window, or ''wsb-mcp stop'' as the broker user. Waiting up to 5 minutes...' -ForegroundColor Yellow
        # The proxy stays alive without a broker and answers tool calls with the offline hint.
        $deadline = (Get-Date).AddMinutes(5)
        do {
            Start-Sleep -Seconds 3
            $r = Invoke-Tool $session.Process 'sandbox_status'
            $offline = $r.IsError -and $r.Text -match 'not reachable'
        } until ($offline -or (Get-Date) -gt $deadline)
        Check 'tools return the offline hint after the broker stopped' $offline $r.Text
        Check 'proxy stays alive without a broker' (-not $session.Process.HasExited) ''
        Write-Host 'On the host, verify that `wsb list` shows no sandbox (the broker stops its guest on shutdown).' -ForegroundColor Yellow
    }
}
catch {
    Check 'unexpected error' $false "$_"
}
finally {
    if ($session -and -not $session.Process.HasExited) { Stop-Proxy $session }
    if (Test-Path -LiteralPath $escape) { [IO.Directory]::Delete($escape) }
    if (Test-Path -LiteralPath $noAccess) {
        $acl = Get-Acl -LiteralPath $noAccess
        $acl.Access | Where-Object { $_.AccessControlType -eq 'Deny' } | ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }
        Set-Acl -LiteralPath $noAccess -AclObject $acl
    }
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}

$failed = @($results | Where-Object { -not $_.Ok }).Count
Write-Host ("{0}/{1} checks passed." -f ($results.Count - $failed), $results.Count)
exit [int]($failed -ne 0)
