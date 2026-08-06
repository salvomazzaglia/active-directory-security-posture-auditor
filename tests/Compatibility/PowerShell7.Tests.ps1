BeforeAll {
    $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    Import-Module (Join-Path $RepoRoot 'ADSecurityPosture/ADSecurityPosture.psd1') -Force
}
Describe 'PowerShell 7 compatibility' {
    It 'module imports under current host' { Get-ADSPVersion | Should -Be '1.0.0' }
    It 'parser accepts module files' {
        $errs = $null
        $null = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $RepoRoot 'ADSecurityPosture/ADSecurityPosture.psm1'), [ref]$null, [ref]$errs)
        @($errs).Count | Should -Be 0
    }
}
