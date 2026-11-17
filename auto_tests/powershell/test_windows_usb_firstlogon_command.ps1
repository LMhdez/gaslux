param(
  [Parameter(Mandatory=$true)][string]$CommandFile
)
$ErrorActionPreference = 'Stop'

# The file contains only the generated Windows Setup command, not a guest script.
$line = (Get-Content -LiteralPath $CommandFile -Raw).TrimEnd("`r", "`n")
$prefix = 'powershell -NoP -EP Bypass -C "'
if (-not $line.StartsWith($prefix) -or -not $line.EndsWith('"')) {
    throw 'Unexpected USB FirstLogon PowerShell invocation'
}
$body = $line.Substring($prefix.Length, $line.Length - $prefix.Length - 1)
if (-not $body.EndsWith(';&$p')) {
    throw 'FirstLogon USB source must end with the checked script invocation'
}

$tokens = $null
$parseErrors = $null
$null = [System.Management.Automation.Language.Parser]::ParseInput(
    $body, [ref]$tokens, [ref]$parseErrors
)
if ($parseErrors.Count -ne 0) {
    throw "Windows USB FirstLogon command failed PowerShell parser: $($parseErrors[0])"
}

$shaMatch = [regex]::Match($body, "Hash-ne '([0-9a-f]{64})'")
if (-not $shaMatch.Success) {
    throw 'No exact SHA-256 check before FirstLogon script execution'
}
$script:expectedHash = $shaMatch.Groups[1].Value
$script:actualHash = $script:expectedHash.ToUpperInvariant()
$script:volumes = @([pscustomobject]@{DriveLetter = 'Z'})
$script:seenLabel = ''
$script:seenPath = ''
$script:hashMockCalls = 0

# Shadow the disk cmdlets: these tests never enumerate real volumes, get a
# real file hash or execute the guest FirstLogon PowerShell script.
function Get-Volume {
    param([string]$FileSystemLabel)
    $script:seenLabel = $FileSystemLabel
    return $script:volumes
}
function Get-FileHash {
    param([string]$Path)
    $script:seenPath = $Path
    $script:hashMockCalls++
    return [pscustomobject]@{Hash = $script:actualHash}
}

$preflight = $body.Substring(0, $body.Length - ';&$p'.Length)
# The mocked function returns only synthetic in-memory records. Log counts
# (never real host volume identities) to explain unexpected PS5.1 behavior.
$synthetic = @(Get-Volume -FileSystemL GASLUXCI)
Write-Output ("GASLUX_PS_SYNTHETIC_VOLUME_COUNT=" + $synthetic.Count)
Write-Output ("GASLUX_PS_FILE_HASH_COMMAND_TYPE=" +
    (Get-Command Get-FileHash).CommandType)
Write-Output ("GASLUX_PS_FILE_HASH_PROBE=" +
    (Get-FileHash -Path 'Z:\GASLUX.PS1').Hash.Length)
Write-Output ("GASLUX_PS_SYNTHETIC_HASH_MATCH=" +
    [int]($script:actualHash -eq $script:expectedHash))
try {
    $resolvedPath = Invoke-Expression ($preflight + ';$p')
} catch {
    throw ("GASLUX_VALID_SYNTHETIC_USB_LOOKUP_FAILED: "
        + $_.Exception.Message + "; mockHashCalls=" + $script:hashMockCalls
        + "; seenPath=" + $script:seenPath + "; seenLabel=" + $script:seenLabel)
}
if ($resolvedPath -ne 'Z:\GASLUX.PS1') {
    throw "Valid unique FAT32 USB did not resolve its dynamic drive"
}
if ($script:seenLabel -ne 'GASLUXCI' -or
    $script:seenPath -ne 'Z:\GASLUX.PS1') {
    throw 'Volume label and hash lookup were not used on the same USB path'
}

$script:volumes = @()
try {
    $null = Invoke-Expression ($preflight + ';$p')
    throw 'FAIL: missing FAT32 volume was accepted'
} catch {
    if ($_.Exception.Message -match '^FAIL:') { throw }
}

$script:volumes = @(
    [pscustomobject]@{DriveLetter = 'Z'},
    [pscustomobject]@{DriveLetter = 'Y'}
)
try {
    $null = Invoke-Expression ($preflight + ';$p')
    throw 'FAIL: ambiguous FAT32 labels were accepted'
} catch {
    if ($_.Exception.Message -match '^FAIL:') { throw }
}

$script:volumes = @([pscustomobject]@{DriveLetter = 'Z'})
$script:actualHash = ('f' * 64)
if ($script:actualHash -eq $script:expectedHash) {
    $script:actualHash = ('0' * 64)
}
try {
    $null = Invoke-Expression ($preflight + ';$p')
    throw 'FAIL: modified script hash was accepted'
} catch {
    if ($_.Exception.Message -match '^FAIL:') { throw }
}

Write-Output 'PASS: Windows PowerShell USB FirstLogon syntax, unique volume, pinned hash; no guest disk or script executed.'
