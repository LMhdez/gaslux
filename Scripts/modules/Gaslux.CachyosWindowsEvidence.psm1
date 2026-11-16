#Requires -Version 5.1
Set-StrictMode -Version Latest

# Read-only Windows 10/11 UEFI/GPT evidence capture for disposable VMs.
# This does NOT perform a CachyOS installation or repair a Windows boot.
# The ESP must ALREADY be mounted by the authorized VM laboratory.

function Get-GasluxEvidenceHash {
    param([Parameter(Mandatory=$true)][string]$Content)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $normalized = $Content.Replace([string][char]13 + [string][char]10, [string][char]10).TrimEnd() + [char]10
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($normalized)
        return [BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-', '').ToLowerInvariant()
    } finally { $sha.Dispose() }
}

function Assert-GasluxWindowsEvidence {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)]$Record)
    $required = @('schemaVersion','runId','computerName','capturedUtc','windowsBootUtc',
        'disk','partitions','esp','windowsLoaderSha256','bcdSha256',
        'firmwareBcdSha256','winReInfoSha256','winReEnabled','bitlocker')
    $fields = @($Record.PSObject.Properties.Name)
    if ($fields.Count -ne $required.Count -or @($fields | Where-Object { $_ -cnotin $required }).Count -gt 0) {
        throw 'Unexpected or missing Windows evidence field.'
    }
    if ($Record.schemaVersion -ne 1 -or
        [string]$Record.runId -cnotmatch '^[A-Za-z0-9_-]{12,100}$' -or
        [string]$Record.computerName -notmatch '^[A-Za-z0-9_.-]{1,80}$' -or
        $Record.winReEnabled -isnot [bool] -or -not $Record.winReEnabled) {
        throw 'Invalid Windows transaction, host or WinRE readiness.'
    }
    foreach ($name in @('capturedUtc','windowsBootUtc')) {
        $parsed = [DateTimeOffset]::MinValue
        if (-not [DateTimeOffset]::TryParse([string]$Record.$name, [ref]$parsed) -or
            $parsed.Offset -ne [TimeSpan]::Zero) {
            throw "Invalid UTC timestamp for $name."
        }
    }
    foreach ($name in @('windowsLoaderSha256','bcdSha256','firmwareBcdSha256','winReInfoSha256')) {
        if ([string]$Record.$name -cnotmatch '^[0-9a-f]{64}$') {
            throw "Invalid SHA-256 for $name."
        }
    }
    $disk = $Record.disk
    if ($null -eq $disk -or [string]$disk.partitionStyle -cne 'GPT' -or
        [string]::IsNullOrWhiteSpace([string]$disk.uniqueId) -or
        [long]$disk.size -le 0 -or
        [int]$disk.logicalSectorSize -notin @(512,4096)) {
        throw 'Invalid Windows GPT disk/sector identity.'
    }
    $partitions = @($Record.partitions)
    if ($partitions.Count -lt 2 -or $partitions.Count -gt 128) {
        throw 'Invalid number of Windows GPT partitions.'
    }
    $usedGuids = @{}
    $lastEnd = [long]0
    foreach ($part in @($partitions | Sort-Object { [long]$_.offset })) {
        $start = [long]$part.offset
        $length = [long]$part.size
        $guid = [string]$part.guid
        if ($length -le 0 -or $start -lt $lastEnd -or
            $start -gt ([long]$disk.size - $length) -or
            $start % [int]$disk.logicalSectorSize -ne 0 -or
            $length % [int]$disk.logicalSectorSize -ne 0 -or
            $guid -notmatch '^[{]?[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}[}]?\z' -or
            $usedGuids.ContainsKey($guid.ToLowerInvariant())) {
            throw 'Overlapping/invalid Windows partition geometry.'
        }
        $usedGuids[$guid.ToLowerInvariant()] = $true
        $lastEnd = $start + $length
    }
    $esp = @($partitions | Where-Object {
        [string]$_.guid -ieq [string]$Record.esp.partitionGuid -and
        [string]$_.gptType -ieq '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}'
    })
    if ($esp.Count -ne 1 -or
        [string]$Record.esp.diskUniqueId -cne [string]$disk.uniqueId) {
        throw 'Windows EFI partition identity is missing/ambiguous.'
    }
    if ([string]$Record.bitlocker.mountPoint -notmatch '^[A-Za-z]:$' -or
        [string]::IsNullOrWhiteSpace([string]$Record.bitlocker.volumeStatus) -or
        [string]::IsNullOrWhiteSpace([string]$Record.bitlocker.protectionStatus) -or
        [string]::IsNullOrWhiteSpace([string]$Record.bitlocker.lockStatus)) {
        throw 'Missing BitLocker/Device Encryption evidence.'
    }
    return $true
}

function Compare-GasluxWindowsRecoveryEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]$Before,
        [Parameter(Mandatory=$true)]$After,
        [switch]$RequireWindowsReboot
    )
    [void](Assert-GasluxWindowsEvidence $Before)
    [void](Assert-GasluxWindowsEvidence $After)
    if ($Before.runId -cne $After.runId -or $Before.computerName -cne $After.computerName) {
        throw 'Windows evidence is from a different host/transaction.'
    }
    $baseline = [ordered]@{}
    $observed = [ordered]@{}
    foreach ($field in @('disk','partitions','esp','windowsLoaderSha256',
        'bcdSha256','firmwareBcdSha256','winReInfoSha256','bitlocker')) {
        $baseline[$field] = $Before.$field
        $observed[$field] = $After.$field
    }
    if ((ConvertTo-Json -InputObject $baseline -Depth 20 -Compress) -cne
        (ConvertTo-Json -InputObject $observed -Depth 20 -Compress)) {
        throw 'Windows geometry, BCD, firmware, WinRE, BitLocker or EFI changed.'
    }
    if ($RequireWindowsReboot -and
        [DateTimeOffset]::Parse([string]$After.windowsBootUtc) -le
        [DateTimeOffset]::Parse([string]$Before.windowsBootUtc)) {
        throw 'No later Windows boot was observed.'
    }
    return [pscustomobject]@{
        schemaVersion = 1
        runId = $Before.runId
        windowsStateMatched = $true
        laterWindowsBootObserved = [bool]$RequireWindowsReboot
        linuxBootVerified = $false
        physicalInstallerReady = $false
    }
}

function Get-GasluxWindowsRecoveryEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][ValidatePattern('^[A-Za-z0-9_-]{12,100}$')][string]$RunId,
        [Parameter(Mandatory=$true)][string]$EspRoot
    )
    if ($env:OS -cne 'Windows_NT') { throw 'Windows VM required.' }
    if ($EspRoot -cnotmatch '^[A-Za-z]:\\$') {
        throw 'Require an already mounted Windows EFI partition (e.g. S:\).'
    }
    # No Add-PartitionAccessPath, mountvol, BCD mutation, disk writes or reboot.
    $drive = [char]$env:SystemDrive[0]
    $osPart = @(Get-Partition -DriveLetter $drive -ErrorAction Stop)
    if ($osPart.Count -ne 1) { throw 'Cannot identify Windows OS partition.' }
    $disk = Get-Disk -Number $osPart[0].DiskNumber -ErrorAction Stop
    if ([string]$disk.PartitionStyle -cne 'GPT') { throw 'UEFI/GPT only.' }
    $partitionData = @(Get-Partition -DiskNumber $disk.Number -ErrorAction Stop)
    $espCandidates = @($partitionData | Where-Object {
        [string]$_.GptType -ieq '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}'
    })
    if ($espCandidates.Count -ne 1) { throw 'Ambiguous EFI partition.' }
    $mounted = @(Get-Partition -AccessPath $EspRoot -ErrorAction Stop)
    if ($mounted.Count -ne 1 -or
        $mounted[0].DiskNumber -ne $disk.Number -or
        [string]$mounted[0].Guid -ne [string]$espCandidates[0].Guid) {
        throw 'Supplied EFI mount is not Windows system ESP.'
    }
    $manager = Join-Path $EspRoot 'EFI\Microsoft\Boot\bootmgfw.efi'
    if (-not (Test-Path -LiteralPath $manager -PathType Leaf)) {
        throw 'Windows Boot Manager missing.'
    }
    $bcd = @(& bcdedit.exe /enum all /v 2>&1)
    if ($LASTEXITCODE -ne 0 -or $bcd.Count -lt 3) { throw 'BCD read failed.' }
    $firmware = @(& bcdedit.exe /enum firmware /v 2>&1)
    if ($LASTEXITCODE -ne 0 -or $firmware.Count -lt 3) { throw 'Firmware BCD read failed.' }
    $winre = @(& reagentc.exe /info 2>&1)
    if ($LASTEXITCODE -ne 0 -or $winre.Count -lt 2) { throw 'WinRE read failed.' }
    $winreEnabled = [bool](($winre -join [Environment]::NewLine) -match
        '(?im)(Windows RE status|Estado do Windows RE|Windows RE-Status)\s*:\s*(Enabled|Ativado|Aktiviert)')
    if (-not $winreEnabled) { throw 'WinRE is disabled or could not be confirmed.' }
    $bit = @(Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop)
    if ($bit.Count -ne 1) { throw 'Device Encryption status unavailable.' }
    $system = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    $parts = @($partitionData | Sort-Object Offset | ForEach-Object {
        [pscustomobject]@{
            number = [int]$_.PartitionNumber
            guid = [string]$_.Guid
            gptType = [string]$_.GptType
            offset = [long]$_.Offset
            size = [long]$_.Size
        }
    })
    $record = [pscustomobject]@{
        schemaVersion = 1
        runId = $RunId
        computerName = [string]$env:COMPUTERNAME
        capturedUtc = [DateTimeOffset]::UtcNow.ToString('o')
        windowsBootUtc = ([DateTimeOffset]$system.LastBootUpTime).ToUniversalTime().ToString('o')
        disk = [pscustomobject]@{
            number = [int]$disk.Number
            uniqueId = [string]$disk.UniqueId
            partitionStyle = [string]$disk.PartitionStyle
            size = [long]$disk.Size
            logicalSectorSize = [int]$disk.LogicalSectorSize
        }
        partitions = $parts
        esp = [pscustomobject]@{
            diskUniqueId = [string]$disk.UniqueId
            partitionGuid = [string]$espCandidates[0].Guid
        }
        windowsLoaderSha256 = ([string](Get-FileHash -Algorithm SHA256 -LiteralPath $manager -ErrorAction Stop).Hash).ToLowerInvariant()
        bcdSha256 = Get-GasluxEvidenceHash ($bcd -join [Environment]::NewLine)
        firmwareBcdSha256 = Get-GasluxEvidenceHash ($firmware -join [Environment]::NewLine)
        winReInfoSha256 = Get-GasluxEvidenceHash ($winre -join [Environment]::NewLine)
        winReEnabled = $true
        bitlocker = [pscustomobject]@{
            mountPoint = [string]$bit[0].MountPoint
            volumeStatus = [string]$bit[0].VolumeStatus
            protectionStatus = [string]$bit[0].ProtectionStatus
            lockStatus = [string]$bit[0].LockStatus
        }
    }
    [void](Assert-GasluxWindowsEvidence $record)
    return $record
}

Export-ModuleMember -Function Get-GasluxWindowsRecoveryEvidence,
    Assert-GasluxWindowsEvidence, Compare-GasluxWindowsRecoveryEvidence
