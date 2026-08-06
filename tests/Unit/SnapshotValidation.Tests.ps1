BeforeAll {
    $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    Import-Module (Join-Path $RepoRoot 'ADSecurityPosture/ADSecurityPosture.psd1') -Force
}
Describe 'Snapshot validation' {
    It 'validates synthetic snapshot' {
        $r = Test-ADSPSnapshot -SnapshotPath (Join-Path $RepoRoot 'examples/synthetic-snapshot/snapshot.json')
        $r.valid | Should -BeTrue
    }
    It 'synthetic marker present in snapshot' {
        $j = Get-Content (Join-Path $RepoRoot 'examples/synthetic-snapshot/snapshot.json') -Raw
        $j | Should -Match 'SYNTHETIC DEMONSTRATION DATA'
        $j | Should -Match 'corp.example.invalid'
    }
    It 'creates deterministic synthetic snapshot with hash' {
        $s = New-ADSPSyntheticSnapshot
        $s.snapshot_hash | Should -Match '^[a-f0-9]{64}$'
        $s.synthetic | Should -BeTrue
    }
    It 'detects hash mismatch when mutated' {
        $tmp = Join-Path $RepoRoot ("temp/mismatch-test-" + [guid]::NewGuid().ToString('N').Substring(0,8))
        New-Item -ItemType Directory -Force -Path $tmp | Out-Null
        $null = New-ADSPSyntheticSnapshot -OutputDirectory $tmp
        $obj = Get-Content (Join-Path $tmp 'snapshot.json') -Raw | ConvertFrom-Json
        $obj.operator_label = 'tampered'
        ($obj | ConvertTo-Json -Depth 100) | Set-Content (Join-Path $tmp 'snapshot.json') -Encoding UTF8
        $r = Test-ADSPSnapshot -SnapshotPath (Join-Path $tmp 'snapshot.json')
        $r.valid | Should -BeFalse
    }
}
