BeforeAll {
    $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    Import-Module (Join-Path $RepoRoot 'ADSecurityPosture/ADSecurityPosture.psd1') -Force
}
Describe 'Collector plans' {
    It 'plan does not execute queries' {
        $p = Get-ADSPCollectionPlan -Domain 'corp.example.invalid' -CollectionProfile Standard
        $p.executes_query | Should -BeFalse
    }
    It 'Minimal profile has fewer collectors than Extended' {
        $profiles = Get-Content (Join-Path $RepoRoot 'config/collection-profiles.json') -Raw | ConvertFrom-Json
        @($profiles.profiles.Minimal.collectors).Count | Should -BeLessThan @($profiles.profiles.Extended.collectors).Count
    }
    It 'Standard includes privileged-membership' {
        $profiles = Get-Content (Join-Path $RepoRoot 'config/collection-profiles.json') -Raw | ConvertFrom-Json
        @($profiles.profiles.Standard.collectors) | Should -Contain 'privileged-membership'
    }
}
