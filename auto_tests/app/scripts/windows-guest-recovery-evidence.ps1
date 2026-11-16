#requires -Version 5.1
<#
Read-only Windows 10/11 UEFI evidence collector for disposable Gaslux guests.
Requires elevation. Writes JSON only to stdout and never mounts ESP or
modifies BCD, partitions, BitLocker, firmware variables or snapshots.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('baseline', 'postinstall', 'rollback')][string]$Phase,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{5,99}$')][string]$RunId
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-GasluxReadOnlyCommand {
    param([string]$Executable, [string[]]$Arguments)
    if (-not (Test-Path -LiteralPath $Executable -PathType Leaf)) {
        throw "Required Windows verification executable is missing: $Executable"
    }
    $lines = @(& $Executable @Arguments 2>&1)
    if ($LASTEXITCODE -ne 0) { throw "Windows verification command failed: $Executable" }
    $out = ($lines | ForEach-Object { [string]$_ }) -join [Environment]::NewLine
    if ([string]::IsNullOrWhiteSpace($out)) { throw 'Windows verifier returned empty evidence.' }
    return $out
}

function Test-GasluxWinReEnabled {
    param([string]$Output)
    # Locale-specific. Unknown translations are refused instead of assumed.
    return [bool]($Output -match '(?im)(Windows\s+RE\s+status|Estado\s+(?:do|de)\s+Windows\s+RE)\s*:\s*(Enabled|Ativado|Activado)\b')
}

function Get-GasluxWindowsEfiHash {
    param($Esp)
    # Get-Volume yields a read-only GUID path without assigning a drive letter.
    $volume = $Esp | Get-Volume -ErrorAction Stop
    $prefix = [string]$volume.Path
    if ($prefix -notmatch '^\\\\\?\\Volume\{[a-fA-F0-9-]{36}\}\\$') {
        throw 'System ESP cannot be accessed by a stable volume GUID path.'
    }
    $loader = $prefix + 'EFI\Microsoft\Boot\bootmgfw.efi'
    if (-not (Test-Path -LiteralPath $loader -PathType Leaf)) {
        throw 'Windows EFI loader is unreadable without mounting the ESP.'
    }
    return (Get-FileHash -LiteralPath $loader -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
}

function Invoke-GasluxWindowsRecoveryEvidence {
    param([string]$EvidencePhase, [string]$EvidenceRunId)
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Evidence collection requires an elevated Windows test VM.'
    }
    if ($env:SystemDrive -notmatch '^[A-Za-z]:$') { throw 'Unexpected Windows system drive.' }
    $winParts = @(Get-Partition -DriveLetter $env:SystemDrive.Substring(0,1) -ErrorAction Stop)
    if ($winParts.Count -ne 1) { throw 'Windows system partition is ambiguous.' }
    $winPart = $winParts[0]
    $winDisk = Get-Disk -Number $winPart.DiskNumber -ErrorAction Stop
    if ([string]$winDisk.PartitionStyle -ne 'GPT' -or
        [string]::IsNullOrWhiteSpace([string]$winDisk.UniqueId)) {
        throw 'UEFI/GPT system disk is not identifiable.'
    }
    $espParts = @(Get-Partition -DiskNumber $winDisk.Number -ErrorAction Stop |
        Where-Object { ([string]$_.GptType).Trim('{}') -ieq 'c12a7328-f81f-11d2-ba4b-00a0c93ec93b' })
    if ($espParts.Count -ne 1) { throw 'Exactly one EFI System Partition is required.' }
    $loaderSha256 = Get-GasluxWindowsEfiHash -Esp $espParts[0]

    $disks = @()
    $diskIdentifiers = @{}
    foreach ($disk in @(Get-Disk -ErrorAction Stop | Sort-Object Number)) {
        $diskId = ([string]$disk.UniqueId).Trim()
        if (-not $diskId -or $diskIdentifiers.ContainsKey($diskId)) {
            throw 'Missing/duplicated stable physical disk identity.'
        }
        $diskIdentifiers[$diskId] = $true
        $partitions = @()
        if ([string]$disk.PartitionStyle -in @('GPT', 'MBR')) {
            foreach ($part in @(Get-Partition -DiskNumber $disk.Number -ErrorAction Stop)) {
                $guid = ([string]$part.Guid).Trim('{}').ToLowerInvariant()
                if ([string]$disk.PartitionStyle -eq 'GPT' -and
                    $guid -notmatch '^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$') {
                    throw 'Missing GPT partition GUID.'
                }
                $partitions += [ordered]@{
                    guid = $guid
                    number = [int]$part.PartitionNumber
                    offset = [int64]$part.Offset
                    size = [int64]$part.Size
                    gptType = ([string]$part.GptType).Trim('{}').ToLowerInvariant()
                    isBoot = [bool]$part.IsBoot
                    isSystem = [bool]$part.IsSystem
                }
            }
        }
        $disks += [ordered]@{
            id = $diskId
            size = [int64]$disk.Size
            logicalSectorSize = [int]$disk.LogicalSectorSize
            partitionStyle = [string]$disk.PartitionStyle
            partitions = @($partitions)
        }
    }

    $winre = Invoke-GasluxReadOnlyCommand -Executable (Join-Path $env:SystemRoot 'System32\reagentc.exe') -Arguments @('/info')
    if (-not (Test-GasluxWinReEnabled -Output $winre)) {
        throw 'Windows Recovery Environment is not provably enabled.'
    }
    $bcd = Join-Path $env:SystemRoot 'System32\bcdedit.exe'
    $bcdCurrent = Invoke-GasluxReadOnlyCommand -Executable $bcd -Arguments @('/enum','{current}','/v')
    $bcdAll = Invoke-GasluxReadOnlyCommand -Executable $bcd -Arguments @('/enum','all','/v')
    $firmware = Invoke-GasluxReadOnlyCommand -Executable $bcd -Arguments @('/enum','firmware','/v')
    if ($bcdCurrent -notmatch '(?i)winload\.efi' -or
        $firmware -notmatch '(?i)bootmgfw\.efi') {
        throw 'Windows BCD/EFI boot executable evidence is missing.'
    }
    if (-not (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue)) {
        throw 'Cannot independently inspect BitLocker/Device Encryption.'
    }
    $encryptedVolumes = @(Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop)
    if ($encryptedVolumes.Count -ne 1) { throw 'BitLocker system volume is ambiguous.' }
    $encrypted = $encryptedVolumes[0]
    $secureBoot = Confirm-SecureBootUEFI -ErrorAction Stop
    if ($secureBoot -isnot [bool]) { throw 'Cannot inspect Secure Boot status.' }

    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    [ordered]@{
        schemaVersion = 1
        source = 'gaslux-windows-guest-readonly-v1'
        phase = $EvidencePhase
        runId = $EvidenceRunId
        capturedAt = [DateTime]::UtcNow.ToString('o')
        computerName = [string]$env:COMPUTERNAME
        windowsVersion = [string]$os.Version
        windowsBootTime = ([DateTime]$os.LastBootUpTime).ToUniversalTime().ToString('o')
        windowsDiskId = ([string]$winDisk.UniqueId).Trim()
        windowsPartitionGuid = ([string]$winPart.Guid).Trim('{}').ToLowerInvariant()
        espPartitionGuid = ([string]$espParts[0].Guid).Trim('{}').ToLowerInvariant()
        windowsEfiSha256 = $loaderSha256
        secureBootEnabled = $secureBoot
        winreEnabled = $true
        winreRaw = $winre
        bcdCurrentRaw = $bcdCurrent
        bcdAllRaw = $bcdAll
        firmwareRaw = $firmware
        bitlocker = [ordered]@{
            protectionStatus = [string]$encrypted.ProtectionStatus
            volumeStatus = [string]$encrypted.VolumeStatus
            encryptionPercentage = [int]$encrypted.EncryptionPercentage
        }
        disks = @($disks)
    } | ConvertTo-Json -Depth 10 -Compress
}
if ($MyInvocation.InvocationName -ne '.') {
    Invoke-GasluxWindowsRecoveryEvidence -EvidencePhase $Phase -EvidenceRunId $RunId
}
