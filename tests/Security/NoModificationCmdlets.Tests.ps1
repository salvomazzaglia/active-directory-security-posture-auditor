BeforeAll {
    $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
}
Describe 'No modification cmdlets' {
    It 'does not contain Set-AD* / New-AD* / Remove-AD* directory modification calls outside denylist docs/tests' {
        $files = Get-ChildItem $RepoRoot -Recurse -Include *.ps1,*.psm1 -File | Where-Object {
            $_.FullName -notmatch '[\\/]\.git[\\/]|[\\/]tests[\\/]|[\\/]temp[\\/]|[\\/]scripts[\\/]_bootstrap|validate-repository\.ps1|run-ci\.ps1'
        }
        $hits = @()
        foreach ($f in $files) {
            $t = Get-Content $f.FullName -Raw
            if ($t -match '(?<!ADSP)(?<!Get-)(?<!Export-)(?<!New-ADSP)(Set-AD\w+|New-AD(?!SP)\w+|Remove-AD\w+|Add-ADGroupMember|Enable-ADAccount|Disable-ADAccount|Unlock-ADAccount|Set-ADAccountPassword)') {
                $hits += $f.FullName
            }
        }
        $hits | Should -BeNullOrEmpty
    }
    It 'does not call Get-LapsADPassword' {
        $hits = Select-String -Path (Join-Path $RepoRoot 'ADSecurityPosture\**\*.ps1'),(Join-Path $RepoRoot 'collectors\*.ps1') -Pattern 'Get-LapsADPassword' -SimpleMatch -ErrorAction SilentlyContinue
        $hits | Should -BeNullOrEmpty
    }
    It 'does not reference mimikatz/rubeus/sharphound/secretsdump in module/collectors' {
        $files = Get-ChildItem (Join-Path $RepoRoot 'ADSecurityPosture'),(Join-Path $RepoRoot 'collectors') -Recurse -File
        foreach ($f in $files) {
            $t = Get-Content $f.FullName -Raw
            $t | Should -Not -Match 'mimikatz|rubeus|sharphound|secretsdump'
        }
    }
}
