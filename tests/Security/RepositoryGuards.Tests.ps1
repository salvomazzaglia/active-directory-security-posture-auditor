BeforeAll {
    $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
}
Describe 'Repository guards' {
    It 'examples use example.invalid domain' {
        $snap = Get-Content (Join-Path $RepoRoot 'examples/synthetic-snapshot/snapshot.json') -Raw
        $snap | Should -Match 'corp\.example\.invalid'
        $snap | Should -Not -Match 'contoso\.com'
        $snap | Should -Not -Match '@gmail\.com'
    }
    It 'actions pinned to full SHAs' {
        $wf = Get-Content (Join-Path $RepoRoot '.github/workflows/ci.yml') -Raw
        $wf | Should -Match 'actions/checkout@[0-9a-f]{40}'
        $wf | Should -Match 'actions/upload-artifact@[0-9a-f]{40}'
    }
    It 'synthetic marker in sample HTML' {
        (Get-Content (Join-Path $RepoRoot 'examples/sample-report.html') -Raw) | Should -Match 'SYNTHETIC DEMONSTRATION DATA'
    }
}
