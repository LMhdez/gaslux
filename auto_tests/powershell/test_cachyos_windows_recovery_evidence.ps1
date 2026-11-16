#Requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..\Scripts\modules')).Path
Import-Module (Join-Path $root 'Gaslux.CachyosWindowsEvidence.psm1') -Force

function Require-Equal {
    param($Actual,$Expected,[string]$What)
    if ($Actual -cne $Expected) { throw "$What mismatch: $Actual != $Expected" }
}
function Require-Failure {
    param([scriptblock]$Action,[string]$Contains)
    $failed = $false
    try { & $Action | Out-Null } catch {
        $failed = $true
        if ([string]$_.Exception.Message -notmatch [regex]::Escape($Contains)) {
            throw "Expected '$Contains' but got: $($_.Exception.Message)"
        }
    }
    if (-not $failed) { throw "Unsafe state was accepted: $Contains" }
}
function New-TestEvidence {
    param([switch]$Rebooted)
    $boot = if ($Rebooted) { '2026-11-16T16:10:00.0000000+00:00' } else { '2026-11-16T15:10:00.0000000+00:00' }
    $capture = if ($Rebooted) { '2026-11-16T17:10:00.0000000+00:00' } else { '2026-11-16T15:30:00.0000000+00:00' }
    return [pscustomobject]@{
        schemaVersion = 1
        runId = 'gaslux-test-case-20261116'
        computerName = 'WINDOWS-VM'
        capturedUtc = $capture
        windowsBootUtc = $boot
        disk = [pscustomobject]@{
            number = 1
            uniqueId = 'GASLUX_TEST_GPT_DISK_0001'
            partitionStyle = 'GPT'
            size = [long]68719476736
            logicalSectorSize = 512
        }
        partitions = @(
            [pscustomobject]@{
                number = 1
                guid = '{11111111-1111-4111-a111-111111111111}'
                gptType = '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}'
                offset = [long]1048576
                size = [long]536870912
            }
            [pscustomobject]@{
                number = 2
                guid = '{22222222-2222-4222-a222-222222222222}'
                gptType = '{ebd0a0a2-b9e5-4433-87c0-68b6b72699c7}'
                offset = [long]537919488
                size = [long]42949672960
            }
        )
        esp = [pscustomobject]@{
            diskUniqueId = 'GASLUX_TEST_GPT_DISK_0001'
            partitionGuid = '{11111111-1111-4111-a111-111111111111}'
        }
        windowsLoaderSha256 = ('a' * 64)
        bcdSha256 = ('b' * 64)
        firmwareBcdSha256 = ('c' * 64)
        winReInfoSha256 = ('d' * 64)
        winReEnabled = $true
        bitlocker = [pscustomobject]@{
            mountPoint = 'C:'
            volumeStatus = 'FullyDecrypted'
            protectionStatus = 'Off'
            lockStatus = 'Unlocked'
        }
    }
}
$cases = 0
function Run-Case {
    param([string]$Name,[scriptblock]$Test)
    & $Test
    $script:cases += 1
    Write-Host "PASS $Name"
}

Run-Case 'unchanged Windows recovery baseline' {
    $before=New-TestEvidence
    $after=New-TestEvidence -Rebooted
    $out=Compare-GasluxWindowsRecoveryEvidence -Before $before -After $after -RequireWindowsReboot
    Require-Equal $out.windowsStateMatched $true 'Windows integrity'
    Require-Equal $out.laterWindowsBootObserved $true 'Windows reboot'
    Require-Equal $out.linuxBootVerified $false 'Linux proof'
    Require-Equal $out.physicalInstallerReady $false 'Hardware release'
}
Run-Case 'fake later boot before baseline collection rejected' {
    $after=New-TestEvidence -Rebooted
    $after.windowsBootUtc='2026-11-16T15:20:00.0000000+00:00'
    Require-Failure { Compare-GasluxWindowsRecoveryEvidence (New-TestEvidence) $after -RequireWindowsReboot } 'Windows did not reboot after'
}
Run-Case 'evidence timestamp from future boot rejected' {
    $after=New-TestEvidence -Rebooted
    $after.windowsBootUtc='2026-11-16T18:10:00.0000000+00:00'
    Require-Failure { Assert-GasluxWindowsEvidence $after } 'later than its evidence capture'
}
Run-Case 'same baseline capture time rejected' {
    $after=New-TestEvidence -Rebooted
    $after.capturedUtc='2026-11-16T15:30:00.0000000+00:00'
    $after.windowsBootUtc='2026-11-16T15:10:00.0000000+00:00'
    Require-Failure { Compare-GasluxWindowsRecoveryEvidence (New-TestEvidence) $after } 'not captured after the baseline'
}
Run-Case 'same Windows boot is not a reboot' {
    $after=New-TestEvidence -Rebooted
    $after.windowsBootUtc='2026-11-16T15:10:00.0000000+00:00'
    Require-Failure { Compare-GasluxWindowsRecoveryEvidence (New-TestEvidence) $after -RequireWindowsReboot } 'Windows did not reboot after'
}
Run-Case 'Windows EFI loader mutation' {
    $other=New-TestEvidence -Rebooted
    $other.windowsLoaderSha256='f' * 64
    Require-Failure { Compare-GasluxWindowsRecoveryEvidence (New-TestEvidence) $other } 'Windows geometry'
}
Run-Case 'BCD mutation' {
    $other=New-TestEvidence -Rebooted
    $other.bcdSha256='f' * 64
    Require-Failure { Compare-GasluxWindowsRecoveryEvidence (New-TestEvidence) $other } 'Windows geometry'
}
Run-Case 'firmware BCD mutation' {
    $other=New-TestEvidence -Rebooted
    $other.firmwareBcdSha256='f' * 64
    Require-Failure { Compare-GasluxWindowsRecoveryEvidence (New-TestEvidence) $other } 'Windows geometry'
}
Run-Case 'WinRE state mismatch' {
    $other=New-TestEvidence -Rebooted
    $other.winReInfoSha256='f' * 64
    Require-Failure { Compare-GasluxWindowsRecoveryEvidence (New-TestEvidence) $other } 'Windows geometry'
}
Run-Case 'WinRE disabled' {
    $other=New-TestEvidence
    $other.winReEnabled=$false
    Require-Failure { Assert-GasluxWindowsEvidence $other } 'Invalid Windows transaction'
}
Run-Case 'BitLocker changed' {
    $other=New-TestEvidence -Rebooted
    $other.bitlocker.protectionStatus='On'
    Require-Failure { Compare-GasluxWindowsRecoveryEvidence (New-TestEvidence) $other } 'Windows geometry'
}
Run-Case 'disk identity changed' {
    $other=New-TestEvidence -Rebooted
    $other.disk.uniqueId='FOREIGN_GPT_DISK_9999'
    Require-Failure { Assert-GasluxWindowsEvidence $other } 'Windows EFI partition identity'
}
Run-Case 'GPT extent modified' {
    $other=New-TestEvidence -Rebooted
    $other.partitions[1].size -= 1048576
    Require-Failure { Compare-GasluxWindowsRecoveryEvidence (New-TestEvidence) $other } 'Windows geometry'
}
Run-Case 'GPT overlapping partitions' {
    $other=New-TestEvidence
    $other.partitions[1].offset=1052672
    Require-Failure { Assert-GasluxWindowsEvidence $other } 'Overlapping'
}
Run-Case 'GPT duplicated partition GUID' {
    $other=New-TestEvidence
    $other.partitions[1].guid=$other.partitions[0].guid
    Require-Failure { Assert-GasluxWindowsEvidence $other } 'Overlapping'
}
Run-Case 'malformed GPT GUID refused' {
    $other=New-TestEvidence
    $other.partitions[1].guid=('{'+ ('-' * 36) +'}')
    Require-Failure { Assert-GasluxWindowsEvidence $other } 'Overlapping'
}
Run-Case 'foreign Windows ESP' {
    $other=New-TestEvidence
    $other.esp.partitionGuid='{33333333-3333-4333-a333-333333333333}'
    Require-Failure { Assert-GasluxWindowsEvidence $other } 'Windows EFI partition'
}
Run-Case 'wrong run ID' {
    $other=New-TestEvidence -Rebooted
    $other.runId='another-gaslux-run-1234'
    Require-Failure { Compare-GasluxWindowsRecoveryEvidence (New-TestEvidence) $other } 'different host/transaction'
}
Run-Case 'wrong Windows computer' {
    $other=New-TestEvidence -Rebooted
    $other.computerName='FOREIGN-WINDOWS'
    Require-Failure { Compare-GasluxWindowsRecoveryEvidence (New-TestEvidence) $other } 'different host/transaction'
}
Run-Case 'extra unauthorized evidence field' {
    $other=New-TestEvidence
    $other | Add-Member -NotePropertyName approved -NotePropertyValue $true
    Require-Failure { Assert-GasluxWindowsEvidence $other } 'Unexpected or missing'
}
Run-Case 'untrusted BCD hash length' {
    $other=New-TestEvidence
    $other.bcdSha256='fakehash'
    Require-Failure { Assert-GasluxWindowsEvidence $other } 'Invalid SHA-256'
}
Run-Case 'wrong firmware partition table' {
    $other=New-TestEvidence
    $other.disk.partitionStyle='MBR'
    Require-Failure { Assert-GasluxWindowsEvidence $other } 'Invalid Windows GPT'
}

Write-Host "PASS: $cases read-only Windows evidence contract tests."
