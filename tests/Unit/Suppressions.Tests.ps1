BeforeAll {
    $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    Import-Module (Join-Path $RepoRoot 'ADSecurityPosture/ADSecurityPosture.psd1') -Force
}
Describe 'Suppressions' {
    It 'example suppression has required fields' {
        $s = (Get-Content (Join-Path $RepoRoot 'config/suppressions.example.json') -Raw | ConvertFrom-Json).suppressions[0]
        $s.justification | Should -Not -BeNullOrEmpty
        $s.expires_at_utc | Should -Not -BeNullOrEmpty
        $s.review_reference | Should -Not -BeNullOrEmpty
    }
}
