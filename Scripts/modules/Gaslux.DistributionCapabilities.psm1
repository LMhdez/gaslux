Set-StrictMode -Version Latest

# Only validate values from an already signature-verified catalog. This
# module deliberately never reads unsigned files and cannot mutate storage.
function Assert-GasluxDistributionCapabilities {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][string]$OsReleaseId,
        [Parameter(Mandatory = $true)][object]$Capabilities
    )

    $profiles = @{
        mint = @('linuxmint', 'debian-squashfs', 'casper-squashfs', 'ms-shim', 'grub', 'grub')
        zorin = @('zorin', 'debian-squashfs', 'casper-squashfs', 'ms-shim', 'grub', 'grub')
        cachyos = @('cachyos', 'archiso-cachyos', 'archiso', 'unsupported', 'grub', 'grub')
        popos = @('pop', 'system76', 'pop-live', 'unsupported', 'grub', 'systemd-boot')
        q4os = @('q4os', 'q4os-native', 'q4os-native-iso', 'unsupported', 'grub', 'grub')
        bazzite = @('bazzite', 'fedora-atomic', 'fedora-atomic-iso', 'manual-enrollment', 'none', 'grub')
    }
    $expected = $profiles[$Id]
    if ($null -eq $expected -or $OsReleaseId -cne $expected[0]) {
        throw 'Unknown or inconsistent distribution identity.'
    }
    $required = @(
        'version', 'backend', 'source', 'firmwareLayouts', 'secureBoot',
        'bootloader', 'status', 'minimumRamMiB', 'minimumDiskGiB'
    )
    $names = @($Capabilities.PSObject.Properties.Name)
    if ($names.Count -ne $required.Count -or
        @($names | Where-Object { $_ -cnotin $required }).Count -gt 0) {
        throw 'Invalid capabilities shape.'
    }
    $bootNames = @($Capabilities.bootloader.PSObject.Properties.Name)
    if ($bootNames.Count -ne 2 -or
        @($bootNames | Where-Object { $_ -cnotin @('bios', 'uefi') }).Count -gt 0) {
        throw 'Invalid bootloader shape.'
    }
    if ($Capabilities.version -isnot [int] -or $Capabilities.version -ne 1 -or
        $Capabilities.backend -cne $expected[1] -or
        $Capabilities.source -cne $expected[2] -or
        $Capabilities.secureBoot -cne $expected[3] -or
        $Capabilities.bootloader.bios -cne $expected[4] -or
        $Capabilities.bootloader.uefi -cne $expected[5]) {
        throw 'Capability backend/source/bootloader mismatch.'
    }
    $layouts = @($Capabilities.firmwareLayouts)
    if ($layouts.Count -lt 1 -or $layouts.Count -gt 2 -or
        @($layouts | Where-Object { $_ -cnotin @('bios/mbr', 'uefi/gpt') }).Count -gt 0 -or
        @($layouts | Select-Object -Unique).Count -ne $layouts.Count -or
        ($Id -eq 'bazzite' -and ($layouts.Count -ne 1 -or $layouts[0] -cne 'uefi/gpt')) -or
        ($Id -in @('mint', 'zorin') -and
         ($layouts.Count -ne 2 -or $layouts[0] -cne 'bios/mbr' -or $layouts[1] -cne 'uefi/gpt')) -or
        ('bios/mbr' -in $layouts -and $Capabilities.bootloader.bios -eq 'none') -or
        ('uefi/gpt' -in $layouts -and $Capabilities.bootloader.uefi -eq 'none')) {
        throw 'Unsupported firmware/partition layout.'
    }
    if ($Capabilities.status -cnotin @('released', 'lab-only', 'unavailable') -or
        ($Capabilities.status -ceq 'released' -and $Id -cnotin @('mint', 'zorin'))) {
        throw 'Experimental backend cannot be released.'
    }
    foreach ($item in @(
        @{ Name = 'minimumRamMiB'; Minimum = 1024 },
        @{ Name = 'minimumDiskGiB'; Minimum = 20 }
    )) {
        $value = $Capabilities.($item.Name)
        if ($value -isnot [int] -or $value -lt $item.Minimum) {
            throw "Invalid capability minimum: $($item.Name)."
        }
    }
    if ($Id -ceq 'bazzite' -and $Capabilities.minimumDiskGiB -lt 50) {
        throw 'Bazzite minimum disk requirement is too low.'
    }
    return $Capabilities.status -ceq 'released'
}

Export-ModuleMember -Function Assert-GasluxDistributionCapabilities
