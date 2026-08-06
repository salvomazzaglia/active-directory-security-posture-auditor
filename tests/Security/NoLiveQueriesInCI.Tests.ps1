BeforeAll {
    $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
}
Describe 'No live queries in CI' {
    It 'workflow does not run collect' {
        $wf = Get-Content (Join-Path $RepoRoot '.github/workflows/ci.yml') -Raw
        $wf | Should -Not -Match 'adsp-audit\.ps1 collect'
        $wf | Should -Not -Match 'AcknowledgeLiveDirectoryQuery'
        $wf | Should -Not -Match 'runs-on:\s*self-hosted'
        $wf | Should -Not -Match 'pull_request_target'
    }
    It 'workflow uses GitHub-hosted runners only' {
        $wf = Get-Content (Join-Path $RepoRoot '.github/workflows/ci.yml') -Raw
        $wf | Should -Match 'windows-latest'
        $wf | Should -Match 'ubuntu-24\.04|ubuntu-latest'
    }
}
