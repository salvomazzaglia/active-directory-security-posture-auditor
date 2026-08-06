BeforeAll {
    $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    Import-Module (Join-Path $RepoRoot 'ADSecurityPosture/ADSecurityPosture.psd1') -Force
    $script:mod = Get-Module ADSecurityPosture
}
Describe 'Reports' {
    It 'sample HTML is standalone without CDN' {
        $html = Get-Content (Join-Path $RepoRoot 'examples/sample-report.html') -Raw
        $html | Should -Match 'SYNTHETIC DEMONSTRATION DATA'
        $html | Should -Not -Match 'cdn\.|googleapis|jsdelivr|unpkg'
    }
    It 'sample JSON has tool metadata' {
        $j = Get-Content (Join-Path $RepoRoot 'examples/sample-report.json') -Raw | ConvertFrom-Json
        $j.tool_version | Should -Be '1.0.0'
        $j.synthetic | Should -BeTrue
    }
    It 'CSV prevents formula injection prefixing' {
        (& $script:mod { ConvertTo-ADSPCsvSafe -Value '=1+1' }) | Should -Be "'=1+1"
        (& $script:mod { ConvertTo-ADSPCsvSafe -Value '+cmd' }) | Should -Be "'+cmd"
        (& $script:mod { ConvertTo-ADSPCsvSafe -Value '-1' }) | Should -Be "'-1"
        (& $script:mod { ConvertTo-ADSPCsvSafe -Value '@a' }) | Should -Be "'@a"
    }
    It 'audit produces json csv html' {
        $out = Join-Path $RepoRoot 'temp/report-test'
        if (Test-Path $out) { Remove-Item $out -Recurse -Force }
        $null = Invoke-ADSPSecurityAudit -SnapshotPath (Join-Path $RepoRoot 'examples/synthetic-snapshot/snapshot.json') -PolicyPath (Join-Path $RepoRoot 'config/baseline.policy.json') -OutputDirectory $out -Format All -PrivacyMode Masked
        Test-Path (Join-Path $out 'report.json') | Should -BeTrue
        Test-Path (Join-Path $out 'report.html') | Should -BeTrue
        Test-Path (Join-Path $out 'findings.csv') | Should -BeTrue
    }
}
