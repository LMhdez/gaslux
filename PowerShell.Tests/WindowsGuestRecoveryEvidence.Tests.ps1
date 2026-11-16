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
