BeforeAll {
    $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    Import-Module (Join-Path $RepoRoot 'ADSecurityPosture/ADSecurityPosture.psd1') -Force
    $script:mod = Get-Module ADSecurityPosture
    $script:policy = & $script:mod { param($p) Resolve-ADSPPolicy -PolicyPath $p } (Join-Path $RepoRoot 'config/baseline.policy.json')
}
Describe 'Scoring' {
    It 'starts at 100 with no findings' {
        $s = & $script:mod { param($p) Get-ADSPScore -Findings @() -Policy $p } $script:policy
        $s.score | Should -Be 100
        $s.grade | Should -Be 'A'
    }
    It 'deducts critical by 25' {
        $f = & $script:mod { New-ADSPFinding -RuleId 'ADSP-X' -Title 't' -Category 'c' -Severity Critical -Result Fail -TargetId 't1' }
        $s = & $script:mod { param($p,$f) Get-ADSPScore -Findings @($f) -Policy $p } $script:policy $f
        $s.score | Should -Be 75
    }
    It 'does not deduct suppressed findings' {
        $f = & $script:mod { New-ADSPFinding -RuleId 'ADSP-X' -Title 't' -Category 'c' -Severity Critical -Result Fail -TargetId 't1' }
        $f.suppressed = $true; $f.result = 'Suppressed'
        $s = & $script:mod { param($p,$f) Get-ADSPScore -Findings @($f) -Policy $p } $script:policy $f
        $s.score | Should -Be 100
    }
    It 'clamps at 0' {
        $findings = & $script:mod {
            1..10 | ForEach-Object { New-ADSPFinding -RuleId "ADSP-$_" -Title 't' -Category 'c' -Severity Critical -Result Fail -TargetId "t$_" }
        }
        $s = & $script:mod { param($p,$f) Get-ADSPScore -Findings $f -Policy $p } $script:policy $findings
        $s.score | Should -Be 0
        $s.grade | Should -Be 'F'
    }
}
