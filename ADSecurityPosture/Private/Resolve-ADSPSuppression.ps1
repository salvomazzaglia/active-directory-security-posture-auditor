function Resolve-ADSPSuppression {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Finding,
        [object[]]$Suppressions,
        $Policy
    )
    if (-not $Suppressions) { return $Finding }
    $now = [datetime]::UtcNow
    foreach ($s in $Suppressions) {
        if (-not $s.enabled) { continue }
        if ($s.rule_id -ne $Finding.rule_id) { continue }
        $created = [datetime]::Parse($s.created_at_utc, $null, [System.Globalization.DateTimeStyles]::RoundtripKind)
        $expires = [datetime]::Parse($s.expires_at_utc, $null, [System.Globalization.DateTimeStyles]::RoundtripKind)
        if ($expires -le $created) { continue }
        if ($now -gt $expires.ToUniversalTime()) { continue }
        if ($Finding.severity -eq 'Critical') {
            $allow = $false
            if ($Policy -and $Policy.thresholds -and (Get-ADSPProp $Policy.thresholds 'allow_critical_suppressions' $false)) { $allow = $true }
            if (-not $allow) { continue }
            if ([string]::IsNullOrWhiteSpace($s.review_reference)) { continue }
            if ([string]::IsNullOrWhiteSpace($s.expires_at_utc)) { continue }
        }
        if ([string]::IsNullOrWhiteSpace($s.justification)) { continue }
        $fp = [string]$s.target_fingerprint
        if ($fp -and $fp -ne '*' -and $Finding.target_id -and $Finding.target_id -ne $fp -and $fp -ne ("{0}:{1}" -f $Finding.target_type, $Finding.target_id)) {
            # allow match on target_id substring fingerprint
            if ($fp -ne $Finding.target_id) { continue }
        }
        if ($fp -eq '*' ) {
            # wildcard disabled by default
            continue
        }
        $Finding.suppressed = $true
        $Finding.suppression_id = $s.id
        $Finding.result = 'Suppressed'
        break
    }
    return $Finding
}

function Get-ADSPScore {
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()][object[]]$Findings = @(),
        [Parameter(Mandatory)]$Policy
    )
    $score = [int]$Policy.scoring.starting_score
    $deductions = @()
    $seen = @{}
    foreach ($f in $Findings) {
        if ($f.suppressed -or $f.result -eq 'Suppressed') { continue }
        if ($f.result -in @('Unavailable','NotApplicable','Pass','Error')) { continue }
        if ($f.result -notin @('Fail','Warning')) { continue }
        $key = "{0}|{1}|{2}" -f $f.rule_id, $f.target_id, $f.severity
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true
        $sev = [string]$f.severity
        $delta = 0
        if ($Policy.scoring.deductions.PSObject.Properties.Name -contains $sev) {
            $delta = [int]$Policy.scoring.deductions.$sev
        }
        if ($delta -gt 0) {
            $score -= $delta
            $deductions += [pscustomobject]@{ rule_id = $f.rule_id; severity = $sev; delta = $delta; target_id = $f.target_id }
        }
    }
    if ($score -lt 0) { $score = 0 }
    if ($score -gt 100) { $score = 100 }
    $grade = 'F'
    $grades = $Policy.scoring.grades
    foreach ($g in @('A','B','C','D','F')) {
        if ($grades.PSObject.Properties.Name -contains $g) {
            $range = @($grades.$g)
            if ($score -ge [int]$range[0] -and $score -le [int]$range[1]) { $grade = $g; break }
        }
    }
    return [pscustomobject]@{
        score = $score
        grade = $grade
        deductions = $deductions
        explanation = 'Score starts at 100. Unsuppressed Fail/Warning findings deduct by severity. Unavailable/NotApplicable/Pass/Suppressed do not reduce the score. The score is a prioritization aid, not certification.'
    }
}

function Get-ADSPExitCode {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Report,
        [ValidateSet('Informational','Low','Medium','High','Critical')]$FailOn = 'High',
        [int]$MinimumScore = 0,
        [switch]$ApplicationError
    )
    if ($ApplicationError) { return 3 }
    $order = @{ Informational = 0; Low = 1; Medium = 2; High = 3; Critical = 4 }
    $threshold = $order[$FailOn]
    $hasPolicyFail = $false
    $hasBelow = $false
    foreach ($f in @($Report.findings)) {
        if ($f.suppressed -or $f.result -eq 'Suppressed') { continue }
        if ($f.result -notin @('Fail','Warning')) { continue }
        $sev = $order[[string]$f.severity]
        if ($sev -ge $threshold) { $hasPolicyFail = $true }
        elseif ($sev -lt $threshold -and $sev -ge 0) { $hasBelow = $true }
    }
    if ($Report.snapshot_hash_status -eq 'Mismatch') { return 2 }
    if ($Report.score -lt $MinimumScore) { return 2 }
    if ($hasPolicyFail) { return 2 }
    if ($Report.internal_error) { return 3 }
    if ($hasBelow -or $Report.snapshot_completeness -eq 'Partial') { return 1 }
    return 0
}

