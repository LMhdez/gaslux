#Requires -Version 5.1
<#
.SYNOPSIS
  Read-only Windows 10/11 laboratory recovery evidence for CachyOS.
.DESCRIPTION
  Run inside a disposable, previously authorized Windows UEFI VM.
  ESP must ALREADY be mounted to the explicit path; this script never mounts
  partitions, changes BCD, edits firmware, changes encryption or reboots.

  Mode Capture emits a baseline JSON document to stdout (caller may redirect
  to a lab-owned evidence file). Mode Compare checks a saved baseline against
  the current Windows state and requires a later Windows boot. It always
  returns physicalInstallerReady=false; a Linux boot is independently required.
.EXAMPLE
  powershell.exe -NoProfile -File Scripts/libertix-cachyos-windows-evidence.ps1 -Mode Capture -RunId vm-run-20261116 -EspRoot S:\
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateSet('Capture','Compare')][string]$Mode,
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Za-z0-9_-]{12,100}$')][string]$RunId,
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Za-z]:\\$')][string]$EspRoot,
    [string]$BaselineJson
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

try {
    $module = Join-Path $PSScriptRoot 'modules\Gaslux.CachyosWindowsEvidence.psm1'
    if (-not (Test-Path -LiteralPath $module -PathType Leaf)) {
        throw 'The trusted Windows evidence module was not deployed.'
    }
    Import-Module -Name $module -Force -ErrorAction Stop
    if ($Mode -ceq 'Compare') {
        if ([string]::IsNullOrWhiteSpace($BaselineJson) -or
            -not (Test-Path -LiteralPath $BaselineJson -PathType Leaf)) {
            throw 'A recorded, independently retained baseline JSON file is required.'
        }
        $item = Get-Item -LiteralPath $BaselineJson -ErrorAction Stop
        if ($item.Length -le 0 -or $item.Length -gt 1048576 -or
            ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
            throw 'Baseline evidence file is empty, too large, or a reparse point.'
        }
        $baseline = Get-Content -LiteralPath $item.FullName -Raw -Encoding UTF8 |
            ConvertFrom-Json -ErrorAction Stop
        [void](Assert-GasluxWindowsEvidence -Record $baseline)
        if ([string]$baseline.runId -cne $RunId) {
            throw 'Baseline belongs to a different installation transaction.'
        }
    }
    $current = Get-GasluxWindowsRecoveryEvidence -RunId $RunId -EspRoot $EspRoot
    if ($Mode -ceq 'Capture') {
        $current | ConvertTo-Json -Depth 20
        exit 0
    }
    $outcome = Compare-GasluxWindowsRecoveryEvidence -Before $baseline -After $current -RequireWindowsReboot
    $outcome | ConvertTo-Json -Depth 20
    exit 0
} catch {
    $failure = [pscustomobject]@{
        ok = $false
        runId = $RunId
        reason = [string]$_.Exception.Message
        windowsRecoveryVerified = $false
        physicalInstallerReady = $false
    }
    $failure | ConvertTo-Json -Depth 5
    exit 1
}
