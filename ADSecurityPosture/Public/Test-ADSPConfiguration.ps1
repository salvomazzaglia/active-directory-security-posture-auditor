function Test-ADSPConfiguration {
    [CmdletBinding()]
    param(
        [string]$ConfigPath = (Join-Path $script:ADSPRepoRoot 'config/default.config.json'),
        [string]$PolicyPath,
        [string]$RulesPath = (Join-Path $script:ADSPRepoRoot 'config/rules.json'),
        [string]$SuppressionsPath
    )
    $errors = New-Object System.Collections.Generic.List[string]
    try {
        $cfg = Get-Content -LiteralPath (Assert-ADSPSafePath -Path $ConfigPath -AllowAbsolute -MustExist) -Raw | ConvertFrom-Json
        if (-not $cfg.schema_version) { $errors.Add('Config missing schema_version') | Out-Null }
    } catch { $errors.Add("Config: $($_.Exception.Message)") | Out-Null }
    try {
        $pack = Get-Content -LiteralPath (Assert-ADSPSafePath -Path $RulesPath -AllowAbsolute -MustExist) -Raw | ConvertFrom-Json
        $ids = @{}
        foreach ($r in $pack.rules) {
            Test-ADSPRuleDefinition -Rule $r | Out-Null
            if ($ids.ContainsKey($r.rule_id)) { $errors.Add("Duplicate rule_id $($r.rule_id)") | Out-Null }
            $ids[$r.rule_id] = $true
        }
        if ($ids.Count -lt 110) { $errors.Add("Rule count $($ids.Count) < 110") | Out-Null }
    } catch { $errors.Add("Rules: $($_.Exception.Message)") | Out-Null }
    if ($PolicyPath) {
        try { Resolve-ADSPPolicy -PolicyPath $PolicyPath | Out-Null } catch { $errors.Add("Policy: $($_.Exception.Message)") | Out-Null }
    }
    if ($SuppressionsPath) {
        try {
            $sup = Get-Content -LiteralPath (Assert-ADSPSafePath -Path $SuppressionsPath -AllowAbsolute -MustExist) -Raw | ConvertFrom-Json
            $sids = @{}
            foreach ($s in $sup.suppressions) {
                if ([string]::IsNullOrWhiteSpace($s.justification)) { $errors.Add("Suppression $($s.id) missing justification") | Out-Null }
                if ($sids.ContainsKey($s.id)) { $errors.Add("Duplicate suppression $($s.id)") | Out-Null }
                $sids[$s.id] = $true
                $c = [datetime]::Parse($s.created_at_utc); $e = [datetime]::Parse($s.expires_at_utc)
                if ($e -le $c) { $errors.Add("Suppression $($s.id) expires before creation") | Out-Null }
            }
        } catch { $errors.Add("Suppressions: $($_.Exception.Message)") | Out-Null }
    }
    return [pscustomobject]@{ valid = ($errors.Count -eq 0); errors = @($errors) }
}
