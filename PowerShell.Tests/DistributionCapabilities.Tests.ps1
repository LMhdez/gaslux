BeforeAll {
    Import-Module "$PSScriptRoot/../Scripts/modules/Gaslux.DistributionCapabilities.psm1" -Force
    function New-Capability {
        param([string]$Backend, [string]$Source, [string]$SecureBoot,
              [string]$Bios, [string]$Uefi, [string]$Status, [string[]]$Layouts)
        [pscustomobject]@{
            version = 1; backend = $Backend; source = $Source
            firmwareLayouts = $Layouts; secureBoot = $SecureBoot
            bootloader = [pscustomobject]@{ bios = $Bios; uefi = $Uefi }
            status = $Status; minimumRamMiB = 8192; minimumDiskGiB = 64
        }
    }
}

Describe 'Signed catalog capability semantics' {
    It 'allows released Mint and Zorin without changing their backend' {
        $mint = New-Capability 'debian-squashfs' 'casper-squashfs' 'ms-shim' 'grub' 'grub' 'released' @('bios/mbr', 'uefi/gpt')
        Assert-GasluxDistributionCapabilities -Id mint -OsReleaseId linuxmint -Capabilities $mint | Should -BeTrue
        Assert-GasluxDistributionCapabilities -Id zorin -OsReleaseId zorin -Capabilities $mint | Should -BeTrue
    }

    It 'rejects experimental release status for <Id>' -ForEach @(
        @{ Id = 'cachyos'; Os = 'cachyos'; Backend = 'archiso-cachyos'; Source = 'archiso'; SB = 'unsupported'; Bios = 'grub'; Uefi = 'grub' },
        @{ Id = 'popos'; Os = 'pop'; Backend = 'system76'; Source = 'pop-live'; SB = 'unsupported'; Bios = 'grub'; Uefi = 'systemd-boot' },
        @{ Id = 'q4os'; Os = 'q4os'; Backend = 'q4os-native'; Source = 'q4os-native-iso'; SB = 'unsupported'; Bios = 'grub'; Uefi = 'grub' },
        @{ Id = 'bazzite'; Os = 'bazzite'; Backend = 'fedora-atomic'; Source = 'fedora-atomic-iso'; SB = 'manual-enrollment'; Bios = 'none'; Uefi = 'grub' }
    ) {
        $cap = New-Capability $Backend $Source $SB $Bios $Uefi 'lab-only' @('uefi/gpt')
        Assert-GasluxDistributionCapabilities -Id $Id -OsReleaseId $Os -Capabilities $cap | Should -BeFalse
        $cap.status = 'released'
        { Assert-GasluxDistributionCapabilities -Id $Id -OsReleaseId $Os -Capabilities $cap } | Should -Throw
    }

    It 'rejects Bazzite BIOS/MBR' {
        $cap = New-Capability 'fedora-atomic' 'fedora-atomic-iso' 'manual-enrollment' 'none' 'grub' 'lab-only' @('bios/mbr', 'uefi/gpt')
        { Assert-GasluxDistributionCapabilities -Id bazzite -OsReleaseId bazzite -Capabilities $cap } | Should -Throw
    }

    It 'rejects mismatched identity even if the backend has a known name' {
        $cap = New-Capability 'debian-squashfs' 'casper-squashfs' 'ms-shim' 'grub' 'grub' 'released' @('bios/mbr', 'uefi/gpt')
        { Assert-GasluxDistributionCapabilities -Id mint -OsReleaseId pop -Capabilities $cap } | Should -Throw
    }
}
