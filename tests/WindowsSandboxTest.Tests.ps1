# SPDX-FileCopyrightText: 2026 Florian Mücke
# SPDX-License-Identifier: MIT
# https://github.com/fmuecke/windows-sandbox-mcp
# Host-only tests for WindowsSandboxTest guest exit-code handling, using a fake
# wsb.exe. Run: pwsh -NoProfile -File tests\WindowsSandboxTest.Tests.ps1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repo = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $repo 'WindowsSandboxTest-1.1.0.psm1') -Force
$fakeWsb = Join-Path $PSScriptRoot 'fake-wsb\wsb.cmd'
$runRoot = Join-Path ([IO.Path]::GetTempPath()) "wsbtest-$([Guid]::NewGuid().ToString('N'))"

$failures = 0
function Test-Case {
    param([string]$Name, [scriptblock]$Body)
    try { & $Body; Write-Host "PASS $Name" }
    catch { $script:failures++; Write-Host "FAIL $Name`n     $_" -ForegroundColor Red }
}
function Invoke-Fake {
    param([scriptblock]$TestScript)
    Invoke-WindowsSandboxTest -RunRoot $runRoot -WsbExecutable $fakeWsb -TestScript $TestScript 6>$null
}
function Assert-Throws {
    param([scriptblock]$Body, [string]$Pattern)
    try { & $Body } catch { if ("$_" -notmatch $Pattern) { throw "Wrong error: $_" }; return }
    throw "Expected an error matching '$Pattern'."
}

try {
    Test-Case 'guest exit 0 succeeds and reports exit code 0' {
        $r = Invoke-Fake { param($s) & $s.InvokeCommand -Command 'cmd.exe /c exit 0' }
        if ($r.ExitCode -ne 0 -or $r.GuestExitCode -ne 0 -or $r.WsbExitCode -ne 0) { throw "Unexpected: $($r | ConvertTo-Json -Compress)" }
    }
    Test-Case 'guest exit 7 throws (wsb.exe exited 0)' {
        Assert-Throws { Invoke-Fake { param($s) & $s.InvokeCommand -Command 'cmd.exe /c exit 7' } } 'failed with exit code 7'
    }
    Test-Case 'guest exit 7 with -CaptureFailure returns ExitCode 7' {
        $r = Invoke-Fake { param($s) & $s.InvokeCommand -Command 'cmd.exe /c exit 7' -CaptureFailure }
        if ($r.ExitCode -ne 7 -or $r.GuestExitCode -ne 7 -or $r.WsbExitCode -ne 0) { throw "Unexpected: $($r | ConvertTo-Json -Compress)" }
    }
    Test-Case 'launch failure throws' {
        Assert-Throws { Invoke-Fake { param($s) & $s.InvokeCommand -Command 'launch-fail' } } 'failed with exit code -2147023584'
    }
    Test-Case 'launch failure with -CaptureFailure returns wsb exit code' {
        $r = Invoke-Fake { param($s) & $s.InvokeCommand -Command 'launch-fail' -CaptureFailure }
        if ($r.ExitCode -ne -2147023584 -or $null -ne $r.GuestExitCode) { throw "Unexpected: $($r | ConvertTo-Json -Compress)" }
    }
    Test-Case 'missing guest exit code throws even with -CaptureFailure' {
        Assert-Throws { Invoke-Fake { param($s) & $s.InvokeCommand -Command 'no-json' -CaptureFailure } } 'did not report a guest exit code'
    }
}
finally {
    if (Test-Path -LiteralPath $runRoot) { Remove-Item -LiteralPath $runRoot -Recurse -Force }
}

if ($failures) { Write-Host "$failures test(s) failed." -ForegroundColor Red; exit 1 }
Write-Host 'All tests passed.'
