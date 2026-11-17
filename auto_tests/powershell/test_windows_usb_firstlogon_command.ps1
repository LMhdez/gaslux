param(
  [Parameter(Mandatory=$true)][string]$CommandFile,
  [Parameter(Mandatory=$true)][string]$ScriptFile
)
$ErrorActionPreference = 'Stop'

# Only one file under the disposable GitHub-hosted Windows runner temp root
# may be mapped as a temporary PSDrive. Never enumerate/modify host disks.
if ($env:GITHUB_ACTIONS -ne 'true' -or
    -not $env:RUNNER_TEMP -or
    -not ([IO.Path]::GetFullPath($ScriptFile)).StartsWith(
        [IO.Path]::GetFullPath($env:RUNNER_TEMP) + [IO.Path]::DirectorySeparatorChar,
        [StringComparison]::OrdinalIgnoreCase
    )) {
    throw 'Refuse non-hosted or foreign Windows guest script fixture'
}
if (-not (Test-Path -LiteralPath $ScriptFile -PathType Leaf)) {
    throw 'Synthetic guest script bytes missing'
}
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
$expectedHash = $shaMatch.Groups[1].Value
$script:volumes = @([pscustomobject]@{DriveLetter = 'Z'})
$script:seenLabel = ''
function Get-Volume {
    param([string]$FileSystemLabel)
    $script:seenLabel = $FileSystemLabel
    return $script:volumes
}
$preflight = $body.Substring(0, $body.Length - ';&$p'.Length)
if (Get-PSDrive -Name Z -ErrorAction SilentlyContinue) {
    throw 'Refuse to replace an existing Windows drive mapping'
}
$root = Split-Path -Parent ([IO.Path]::GetFullPath($ScriptFile))
$null = New-PSDrive -Name Z -PSProvider FileSystem -Root $root -Scope Script
try {
    # The *actual* native Get-FileHash reads only our one temporary script.
    # The witness script is never executed (remove the final & $p).
    $actualHash = (Get-FileHash -LiteralPath $ScriptFile -Algorithm SHA256).Hash
    if ($actualHash -ne $expectedHash) {
        throw 'Generated guest file does not match inline SHA-256 before test'
    }

    $resolvedPath = Invoke-Expression ($preflight + ';$p')
    if ($resolvedPath -ne 'Z:\GASLUX.PS1' -or
        $script:seenLabel -ne 'GASLUXCI') {
        throw 'Unique FAT32 label and real hash did not resolve expected path'
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
    Set-Content -LiteralPath $ScriptFile -Encoding ascii -Value '# synthetic tampered script never executed'
    try {
        $null = Invoke-Expression ($preflight + ';$p')
        throw 'FAIL: modified script hash was accepted'
    } catch {
        if ($_.Exception.Message -match '^FAIL:') { throw }
    }
    Write-Output 'PASS: native Windows PS5.1/PS7 checks real SHA256 on temporary file and fails closed for missing/duplicate label and tampering. No guest disk.'
} finally {
    Remove-PSDrive -Name Z -Scope Script -ErrorAction Stop
}
