# Native Windows PowerShell lexical/evaluation contract for COM1 first logon.
# No COM1, QEMU, Windows Setup or disk writes.
$ErrorActionPreference = 'Stop'
$sourceFile = Join-Path $PSScriptRoot 'win-firstlogon-source.ps1'
if (-not (Test-Path -LiteralPath $sourceFile -PathType Leaf)) {
    throw 'Missing Python-generated first-logon PowerShell source'
}
$tokens = $null
$parseErrors = $null
[System.Management.Automation.Language.Parser]::ParseFile(
    $sourceFile, [ref]$tokens, [ref]$parseErrors
) | Out-Null
if ($parseErrors.Count -ne 0) {
    throw 'Real Windows PowerShell parser rejected first-logon source'
}
$source = Get-Content -LiteralPath $sourceFile -Raw
$match = [regex]::Match(
    $source,
    '(?ms)^\$serialProof\s*=\s*@\(\r?\n(?<items>.*?)^\s*\)\s*$'
)
if (-not $match.Success) {
    throw 'Missing bounded native serial marker array'
}
$os = [pscustomobject]@{ BuildNumber = '19045' }
$markerSnippet = '$serialProof = @(' + [Environment]::NewLine + $match.Groups['items'].Value + [Environment]::NewLine + ')'
. ([scriptblock]::Create($markerSnippet))
$observed = @($serialProof)
Write-Host ("GASLUX_WINDOWS_SERIAL_MARKER_ELEMENT_COUNT={0}" -f $observed.Count)
if ($observed.Count -ne 7) {
    throw 'PowerShell constructed incorrect number of individual serial markers'
}
$expected = @(
    'GASLUX_WINDOWS_X64_BOOT_BUILD=19045'
    'GASLUX_WINDOWS_X64_BOOT_PRODUCTTYPE=1'
    'GASLUX_WINDOWS_X64_GPT_ESP_COUNT=1'
    'GASLUX_WINDOWS_X64_RECOVERY_GPT_COUNT=1'
    'GASLUX_WINDOWS_X64_BCD_ENUMERATED=1'
    'GASLUX_WINDOWS_X64_WINRE_ENABLED=1'
    '__MARKER__=__PROFILE__'
)
for ($i = 0; $i -lt $expected.Count; $i++) {
    if ($observed[$i] -isnot [string]) {
        throw "Serial element $i is not a string; array-to-string conversion is unsafe"
    }
    if ($observed[$i] -cne $expected[$i]) {
        throw "Serial element $i is missing or contains concatenated markers"
    }
    if ($observed[$i] -match '\s') {
        throw "Serial element $i contains embedded marker separators"
    }
}
if (-not $source.Contains('$ser.NewLine = "' + [char]96 + 'n"')) {
    throw 'Windows COM1 witness must set an explicit LF line delimiter'
}
Write-Host 'GASLUX_WINDOWS_SERIAL_MARKERS_INDIVIDUAL_LINES_CONTRACT_PASS=1'
