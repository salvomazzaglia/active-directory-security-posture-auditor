BeforeAll {
    $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    Import-Module (Join-Path $RepoRoot 'ADSecurityPosture/ADSecurityPosture.psd1') -Force
    $script:AdspModule = Get-Module ADSecurityPosture
}
Describe 'Path safety' {
    It 'accepts project-relative path for existing snapshot' {
        $p = Join-Path $RepoRoot 'examples/synthetic-snapshot/snapshot.json'
        Test-Path $p | Should -BeTrue
    }
    It 'rejects traversal via Assert-ADSPSafePath' {
        { & $script:AdspModule { Assert-ADSPSafePath -Path '../..' } } | Should -Throw
    }
    It 'rejects NUL' {
        { & $script:AdspModule { Assert-ADSPSafePath -Path ("a$([char]0)b") } } | Should -Throw
    }
    It 'rejects output inside module source' {
        { & $script:AdspModule { Assert-ADSPSafePath -Path (Join-Path $RepoRoot 'ADSecurityPosture/out') -IsOutput -AllowAbsolute } } | Should -Throw
    }
}
