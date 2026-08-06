BeforeAll {
    $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    Import-Module (Join-Path $RepoRoot 'ADSecurityPosture/ADSecurityPosture.psd1') -Force
}
Describe 'Blocked attributes in collectors' {
    It 'collector property lists never include blocked attributes' {
        $blocked = (Get-Content (Join-Path $RepoRoot 'config/sensitive-attributes.json') -Raw | ConvertFrom-Json).blocked_attributes
        foreach ($f in Get-ChildItem (Join-Path $RepoRoot 'collectors') -Filter *.ps1) {
            $t = Get-Content $f.FullName -Raw
            foreach ($b in $blocked) {
                $t | Should -Not -Match ("'" + [regex]::Escape($b) + "'")
            }
            $t | Should -Not -Match '-Properties\s+\*'
        }
    }
}
