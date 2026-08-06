BeforeAll {
    $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
}
Describe 'PowerShell 5.1 syntax compatibility' {
    It 'public scripts parse without errors' {
        $files = Get-ChildItem (Join-Path $RepoRoot 'ADSecurityPosture') -Recurse -Include *.ps1,*.psm1
        foreach ($f in $files) {
            $errs = $null
            $null = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$null, [ref]$errs)
            @($errs).Count | Should -Be 0
        }
    }
}
