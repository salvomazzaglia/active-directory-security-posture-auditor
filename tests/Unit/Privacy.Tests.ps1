BeforeAll {
    $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    Import-Module (Join-Path $RepoRoot 'ADSecurityPosture/ADSecurityPosture.psd1') -Force
    $script:mod = Get-Module ADSecurityPosture
}
Describe 'Privacy' {
    It 'masks domain values' {
        $v = & $script:mod {
            $map = @{}
            ConvertTo-ADSPPrivacyValue -Value 'corp.example.invalid' -PrivacyMode Masked -Kind domain -AliasMap $map
        }
        $v | Should -Match '^DOMAIN-'
    }
    It 'requires salt for hashed mode' {
        Remove-Item Env:ADSP_PRIVACY_SALT -ErrorAction SilentlyContinue
        { & $script:mod { ConvertTo-ADSPPrivacyValue -Value 'user1' -PrivacyMode Hashed -Kind user } } | Should -Throw
    }
    It 'hashes with salt and never returns salt' {
        $v = & $script:mod { ConvertTo-ADSPPrivacyValue -Value 'user1' -PrivacyMode Hashed -Kind user -Salt 'test-salt' }
        $v | Should -Match '^USER-'
        $v | Should -Not -Match 'test-salt'
    }
    It 'full mode returns original with warning path available' {
        $v = & $script:mod { ConvertTo-ADSPPrivacyValue -Value 'synthetic-admin' -PrivacyMode Full -Kind user }
        $v | Should -Be 'synthetic-admin'
    }
    It 'redacts sensitive values' {
        (& $script:mod { Protect-ADSPSensitiveValue -Value 'secret' }) | Should -Be '[REDACTED]'
    }
}
