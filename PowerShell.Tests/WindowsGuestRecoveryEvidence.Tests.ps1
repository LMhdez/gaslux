#requires -Version 5.1
BeforeAll {
    # Dot-source helper functions only; never probe CI runner boot state.
    . "$PSScriptRoot/../auto_tests/app/scripts/windows-guest-recovery-evidence.ps1" -Phase baseline -RunId fixture-test-12345
}
Describe 'Windows guest read-only evidence parser' {
    It 'accepts English WinRE enabled' {
        Test-GasluxWinReEnabled -Output 'Windows RE status: Enabled' | Should -BeTrue
    }
    It 'accepts Portuguese WinRE enabled' {
        Test-GasluxWinReEnabled -Output 'Estado do Windows RE: Ativado' | Should -BeTrue
    }
    It 'rejects WinRE disabled' {
        Test-GasluxWinReEnabled -Output 'Windows RE status: Disabled' | Should -BeFalse
    }
    It 'rejects unknown recovery locale' {
        Test-GasluxWinReEnabled -Output 'Stato Windows RE: Attivo' | Should -BeFalse
    }
    It 'accepts WinRE WIM on the selected Windows disk without mounting' {
        $info = 'Windows RE location: \\?\GLOBALROOT\device\harddisk0\partition4\Recovery\WindowsRE'
        Get-GasluxWinReImagePath -Info $info -SystemDiskNumber 0 |
            Should -Be '\\?\GLOBALROOT\device\harddisk0\partition4\Recovery\WindowsRE\winre.wim'
    }
    It 'refuses WinRE image from an unrelated disk' {
        $info = 'Windows RE location: \\?\GLOBALROOT\device\harddisk1\partition4\Recovery\WindowsRE'
        { Get-GasluxWinReImagePath -Info $info -SystemDiskNumber 0 } | Should -Throw
    }
    It 'contains no disk or boot mutation command' {
        $source = Get-Content -LiteralPath "$PSScriptRoot/../auto_tests/app/scripts/windows-guest-recovery-evidence.ps1" -Raw
        foreach ($name in @(
            'Set-Partition', 'Remove-Partition', 'New-Partition',
            'Format-Volume', 'Resize-Partition', 'Set-Disk',
            'mountvol.exe', 'Set-BitLockerVolume', 'Disable-BitLocker',
            'Set-Content', 'Remove-Item', 'Set-ItemProperty'
        )) {
            $source | Should -Not -Match ([regex]::Escape($name))
        }
    }
}
