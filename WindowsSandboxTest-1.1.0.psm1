# Copyright (c) 2026 Florian Mücke
# SPDX-License-Identifier: MIT
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# Version: 1.1.0
#
# Changes:
# 1.1.0 - InvokeCommand now evaluates the guest process exit code reported by
#         `wsb --raw exec` ({"ExitCode": n}). wsb.exe itself exits 0 whenever the
#         guest process was launched, so 1.0.0 treated failing guest commands as
#         success. A nonzero guest exit code now throws unless -CaptureFailure is
#         given. Result.ExitCode is the guest exit code (or the wsb.exe exit code
#         if the launch failed); WsbExitCode and GuestExitCode are reported
#         separately.
#
# Purpose: simplify execution of risky tests with Windows Sandbox, keeping
# elevated or destructive test effects inside a fresh, disposable guest.
#
# Flow:
# 1. Refuse to attach to an existing Windows Sandbox, then stage artifacts in a
#    unique host directory and start a fresh unconfigured guest.
# 2. Retry a writable share of that directory until the guest is ready.
# 3. Give the callback the host/guest paths plus an InvokeCommand delegate that
#    dispatches through the sole wsb.exe gateway as SYSTEM by default.
# 4. Let the caller validate its own output and success criteria, then always
#    stop the guest and report phase and total timings.
#
# Quick start:
#   Import-Module .\WindowsSandboxTest.psm1
#   Invoke-WindowsSandboxTest `
#       -RunRoot .\out\sandbox-tests `
#       -ArtifactPath .\out\my-elevated-tests.exe `
#       -TestScript {
#           param($sandbox)
#           $result = & $sandbox.InvokeCommand `
#               -Command 'my-elevated-tests.exe' `
#               -Phase 'Elevated tests'
#           $result.Output
#       }
#
# RunRoot is a host path, normally below the current project's build output.
# The helper creates a GUID-named child there; staged files and results remain
# owned by the host caller. GuestMountPath is the location at which that host
# directory appears inside the disposable guest. It defaults to the dedicated 
# guest-only path C:\SandboxTest.
#
# The callback runs only after the artifact directory is shared. Its context
# contains HostDirectory, GuestMountPath, and InvokeCommand. InvokeCommand runs
# as SYSTEM unless -RunAs is specified. Validate project-specific markers in
# the callback; the helper preserves the host directory and writes callback
# output to the success stream. InvokeCommand throws when the guest command
# exits nonzero; pass -CaptureFailure to inspect ExitCode yourself instead.
# wsb exec does not return guest stdout/stderr: redirect guest output to a file
# below GuestMountPath and read it from HostDirectory. Use -PassThru to
# receive that directory and the callback output together instead.

# Sample code to use this gist:
#
# $runRoot = Join-Path $repositoryRoot 'out\windows-sandbox-integration'
# # Update the immutable raw revision and SHA-256 together when publishing a new
# # WindowsSandboxTest module version.
# $windowsSandboxTestModuleUri = 'https://gist.githubusercontent.com/fmuecke/2a53528dba05cd208c2cfbef2c547e2a/raw/<commit hash>/WindowsSandboxTest.psm1'
# $windowsSandboxTestModuleSha256 = '<calculated hash>'
# $windowsSandboxTestModulePath = Join-Path $runRoot 'WindowsSandboxTest-1.1.0.psm1'
# $windowsSandboxTestDownloadPath = "$windowsSandboxTestModulePath.download"
# New-Item -ItemType Directory -Path $runRoot -Force | Out-Null
# try {
#     Invoke-WebRequest -Uri $windowsSandboxTestModuleUri -OutFile $windowsSandboxTestDownloadPath
#     $downloadedHash = (Get-FileHash -LiteralPath $windowsSandboxTestDownloadPath -Algorithm SHA256).Hash
#     if ($downloadedHash -ne $windowsSandboxTestModuleSha256) {
#         throw "WindowsSandboxTest 1.1.0 hash mismatch. Expected $windowsSandboxTestModuleSha256, got $downloadedHash."
#     }
#     Move-Item -LiteralPath $windowsSandboxTestDownloadPath -Destination $windowsSandboxTestModulePath -Force
# }
# finally {
#     if (Test-Path -LiteralPath $windowsSandboxTestDownloadPath) {
#         Remove-Item -LiteralPath $windowsSandboxTestDownloadPath -Force
#     }
# }
# Import-Module $windowsSandboxTestModulePath -Force


Set-StrictMode -Version Latest

function Invoke-WsbRaw {
    param(
        [Parameter(Mandatory)][string]$Executable,
        [Parameter(Mandatory)][string[]]$Arguments,
        [switch]$CaptureFailure
    )

    # PowerShell 7 can otherwise turn a native nonzero exit into a terminating
    # error before callers have a chance to inspect the exit code and output.
    $PSNativeCommandUseErrorActionPreference = $false
    $output = & $Executable --raw @Arguments 2>&1 | Out-String
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0 -and -not $CaptureFailure) {
        throw "wsb $($Arguments -join ' ') failed with exit code $exitCode.`n$output"
    }
    return [PSCustomObject]@{
        Output   = $output
        ExitCode = $exitCode
    }
}

function Find-WsbId {
    param([Parameter(Mandatory)]$Value)

    if ($Value -is [string]) {
        return $null
    }
    foreach ($property in $Value.PSObject.Properties) {
        if ($property.Name -ieq 'id' -and $property.Value -is [string] -and $property.Value) {
            return $property.Value
        }
        $nested = Find-WsbId -Value $property.Value
        if ($nested) {
            return $nested
        }
    }
    return $null
}

function Write-SandboxTiming {
    param(
        [Parameter(Mandatory)]$Timing,
        [Parameter(Mandatory)][string]$Phase
    )

    $totalSeconds = $Timing.Stopwatch.Elapsed.TotalSeconds
    $phaseSeconds = $totalSeconds - $Timing.LastSeconds
    $Timing.LastSeconds = $totalSeconds
    Write-Host ([string]::Format(
            [Globalization.CultureInfo]::InvariantCulture,
            '{0}: {1:F2} secs (total {2:F2} secs)',
            $Phase, $phaseSeconds, $totalSeconds))
}

function Invoke-WindowsSandboxTest {
    <#
    .SYNOPSIS
    Runs a test callback in a fresh Windows Sandbox and always stops the guest.

    .DESCRIPTION
    Refuses to attach to an existing guest, stages the requested artifacts in a
    unique writable host directory, starts and shares a fresh guest, and gives
    the callback an InvokeCommand delegate that runs as SYSTEM by default.

    The callback receives one context object with HostDirectory,
    GuestMountPath, and InvokeCommand properties. InvokeCommand accepts
    -Command, -Phase, -WorkingDirectory, -RunAs, and -CaptureFailure. It
    throws when wsb cannot launch the command or the guest command exits
    nonzero, unless -CaptureFailure is given. It returns Output (raw wsb JSON),
    ExitCode (guest exit code, or the wsb.exe exit code if the launch failed),
    WsbExitCode, and GuestExitCode. Guest stdout/stderr is not returned;
    redirect it to a file below GuestMountPath. By default, callback output
    is written to the success stream; -PassThru returns it together with the
    retained HostDirectory instead.

    .EXAMPLE
    Invoke-WindowsSandboxTest `
        -RunRoot '.\out\sandbox-tests' `
        -ArtifactPath '.\out\my-elevated-tests.exe' `
        -TestScript {
            param($sandbox)
            & $sandbox.InvokeCommand `
                -Command 'my-elevated-tests.exe' `
                -Phase 'Elevated tests'
        }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$RunRoot,
        [ValidateNotNullOrEmpty()][string]$GuestMountPath = 'C:\SandboxTest',
        [Parameter(Mandatory)][ValidateNotNull()][scriptblock]$TestScript,
        [ValidateNotNull()][string[]]$ArtifactPath = @(),
        [ValidateRange(1, 600)][int]$StartupTimeoutSeconds = 120,
        [ValidateRange(0, 60)][int]$ShareRetryIntervalSeconds = 2,
        [ValidateNotNullOrEmpty()][string]$WsbExecutable = 'wsb.exe',
        [switch]$PassThru
    )

    $resolvedExecutable = (Get-Command -Name $WsbExecutable -CommandType Application -ErrorAction Stop).Source

    $artifacts = @(
        foreach ($path in $ArtifactPath) {
            Get-Item -LiteralPath $path -ErrorAction Stop
        }
    )
    $duplicateNames = @(
        $artifacts |
        Group-Object -Property Name |
        Where-Object Count -gt 1 |
        ForEach-Object -MemberName Name
    )
    if ($duplicateNames.Count -ne 0) {
        throw "Artifact names must be unique: $($duplicateNames -join ', ')"
    }

    $running = (Invoke-WsbRaw -Executable $resolvedExecutable -Arguments @('list')).Output |
    ConvertFrom-Json
    if (@($running.WindowsSandboxEnvironments).Count -ne 0) {
        throw 'A Windows Sandbox is already running; refuse to attach the isolated test.'
    }

    $resolvedRunRoot = (New-Item -ItemType Directory -Path $RunRoot -Force).FullName
    $runId = [Guid]::NewGuid().ToString('N')
    $hostDirectory = Join-Path $resolvedRunRoot $runId
    New-Item -ItemType Directory -Path $hostDirectory | Out-Null
    foreach ($artifact in $artifacts) {
        Copy-Item -LiteralPath $artifact.FullName -Destination $hostDirectory -Recurse
    }

    Write-Host ''
    Write-Host 'Starting a fresh Windows Sandbox for isolated tests...'

    $sandboxId = $null
    $testOutput = @()
    $testError = $null
    $stopError = $null
    $timing = [PSCustomObject]@{
        Stopwatch   = [Diagnostics.Stopwatch]::StartNew()
        LastSeconds = 0.0
    }

    try {
        $started = (Invoke-WsbRaw -Executable $resolvedExecutable -Arguments @('start')).Output |
        ConvertFrom-Json
        $sandboxId = Find-WsbId -Value $started
        if (-not $sandboxId) {
            throw "wsb start did not return a sandbox id: $($started | ConvertTo-Json -Depth 8)"
        }
        Write-SandboxTiming -Timing $timing -Phase 'Sandbox start'

        $deadline = (Get-Date).AddSeconds($StartupTimeoutSeconds)
        $lastShareError = $null
        do {
            try {
                Invoke-WsbRaw -Executable $resolvedExecutable -Arguments @(
                    'share', '--id', $sandboxId, '-f', $hostDirectory,
                    '-s', $GuestMountPath, '-w') | Out-Null
                $lastShareError = $null
                break
            }
            catch {
                $lastShareError = $_
                if ($ShareRetryIntervalSeconds -ne 0) {
                    Start-Sleep -Seconds $ShareRetryIntervalSeconds
                }
            }
        } while ((Get-Date) -lt $deadline)
        if ($lastShareError) {
            throw "Windows Sandbox did not accept the shared test directory.`n$lastShareError"
        }
        Write-SandboxTiming -Timing $timing -Phase 'Sandbox ready and shared folder mounted'

        $invokeCommand = {
            [CmdletBinding()]
            param(
                [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Command,
                [ValidateNotNullOrEmpty()][string]$Phase = 'Guest command',
                [ValidateNotNullOrEmpty()][string]$WorkingDirectory = $GuestMountPath,
                [ValidateNotNullOrEmpty()][string]$RunAs = 'system',
                [switch]$CaptureFailure
            )

            $raw = Invoke-WsbRaw -Executable $resolvedExecutable -Arguments @(
                'exec', '--id', $sandboxId, '-d', $WorkingDirectory,
                '-r', $RunAs, '-c', $Command) -CaptureFailure:$CaptureFailure
            Write-SandboxTiming -Timing $timing -Phase $Phase

            # wsb.exe exits 0 once the guest process was launched; the guest
            # process exit code is only reported in the JSON output.
            $guestExitCode = $null
            if ($raw.ExitCode -eq 0) {
                $exitCodeProperty = $null
                try {
                    $parsed = $raw.Output | ConvertFrom-Json -ErrorAction Stop
                    if ($null -ne $parsed -and $parsed -isnot [string]) {
                        $exitCodeProperty = $parsed.PSObject.Properties['ExitCode']
                    }
                }
                catch {
                    $exitCodeProperty = $null
                }
                if ($null -eq $exitCodeProperty -or $null -eq ($exitCodeProperty.Value -as [int])) {
                    throw "wsb exec did not report a guest exit code for '$Command'.`n$($raw.Output)"
                }
                $guestExitCode = [int]$exitCodeProperty.Value
                if ($guestExitCode -ne 0 -and -not $CaptureFailure) {
                    throw "Guest command '$Command' ($Phase) failed with exit code $guestExitCode."
                }
            }

            return [PSCustomObject]@{
                Output        = $raw.Output
                ExitCode      = if ($null -ne $guestExitCode) { $guestExitCode } else { $raw.ExitCode }
                WsbExitCode   = $raw.ExitCode
                GuestExitCode = $guestExitCode
            }
        }

        $context = [PSCustomObject]@{
            HostDirectory  = $hostDirectory
            GuestMountPath = $GuestMountPath
            InvokeCommand  = $invokeCommand
        }
        $testOutput = @(& $TestScript $context)
    }
    catch {
        $testError = $_
    }
    finally {
        try {
            if ($sandboxId) {
                Invoke-WsbRaw -Executable $resolvedExecutable -Arguments @(
                    'stop', '--id', $sandboxId) | Out-Null
            }
        }
        catch {
            $stopError = $_
        }
        finally {
            $timing.Stopwatch.Stop()
            Write-SandboxTiming -Timing $timing -Phase 'Sandbox teardown'
            Write-Host ([string]::Format(
                    [Globalization.CultureInfo]::InvariantCulture,
                    'Windows Sandbox test duration: {0:F2} secs',
                    $timing.Stopwatch.Elapsed.TotalSeconds))
        }
    }

    if ($testError -and $stopError) {
        throw "The isolated test failed and Windows Sandbox cleanup also failed.`nTest failure: $testError`nCleanup failure: $stopError"
    }
    if ($testError) {
        throw $testError
    }
    if ($stopError) {
        throw $stopError
    }

    if ($PassThru) {
        return [PSCustomObject]@{
            HostDirectory = $hostDirectory
            Output        = $testOutput
        }
    }
    Write-Output $testOutput
}

Export-ModuleMember -Function Invoke-WindowsSandboxTest
