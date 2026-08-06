BeforeAll {
    $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    Import-Module (Join-Path $RepoRoot 'ADSecurityPosture/ADSecurityPosture.psd1') -Force
    $script:mod = Get-Module ADSecurityPosture
}
Describe 'Membership expansion' {
    It 'expands direct membership' {
        $idx = @{ 'G1' = @('U1') }
        $principals = @{ 'U1' = [pscustomobject]@{ class='user' } }
        $r = & $script:mod { param($i,$p) Expand-ADSPGroupMembership -GroupKey 'G1' -MembershipIndex $i -PrincipalIndex $p } $idx $principals
        $r.Members.Count | Should -Be 1
        $r.Members[0].membership_type | Should -Be 'Direct'
    }
    It 'expands nested membership' {
        $idx = @{ 'G1' = @('G2'); 'G2' = @('U1') }
        $principals = @{ 'U1' = [pscustomobject]@{ class='user' }; 'G2' = [pscustomobject]@{ class='group' } }
        $r = & $script:mod { param($i,$p) Expand-ADSPGroupMembership -GroupKey 'G1' -MembershipIndex $i -PrincipalIndex $p } $idx $principals
        ($r.Members | Where-Object member_key -eq 'U1').membership_type | Should -Be 'Transitive'
    }
    It 'detects cycles without infinite loop' {
        $idx = @{ 'A' = @('B'); 'B' = @('A') }
        $principals = @{}
        $r = & $script:mod { param($i,$p) Expand-ADSPGroupMembership -GroupKey 'A' -MembershipIndex $i -PrincipalIndex $p -MaxDepth 5 } $idx $principals
        $r.CycleDetected | Should -BeTrue
    }
    It 'respects depth limit' {
        $idx = @{ 'G1'=@('G2'); 'G2'=@('G3'); 'G3'=@('U1') }
        $r = & $script:mod { param($i) Expand-ADSPGroupMembership -GroupKey 'G1' -MembershipIndex $i -PrincipalIndex @{} -MaxDepth 1 } $idx
        ($r.Members | Where-Object member_key -eq 'U1') | Should -BeNullOrEmpty
    }
}
