function Invoke-ADSPCollector_password_policies {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Context)
    $started = [datetime]::UtcNow
    $moduleRequired = 'ActiveDirectory'
    $available = if ($moduleRequired -eq 'GroupPolicy') { [bool]$Context.GroupPolicyAvailable } else { [bool]$Context.ActiveDirectoryAvailable }
    $props = @('objectGuid', 'name', 'distinguishedName')
    $props = @($props | Where-Object { $n = $_; -not (@($Context.BlockedAttributes) | Where-Object { $_ -ieq $n }) })
    if ($props -contains '*') { throw 'Properties wildcard is forbidden.' }
    if (-not $available) {
        return [pscustomobject]@{
            collector_id = 'password-policies'
            category = 'live'
            status = 'Unavailable'
            started_at_utc = $started.ToString('o')
            completed_at_utc = [datetime]::UtcNow.ToString('o')
            duration_ms = 0
            source_mode = 'Live'
            module_required = $moduleRequired
            module_available = $false
            objects_examined = 0
            records_emitted = 0
            truncated = $false
            warnings = @('Required module not available. Module was not installed automatically.')
            errors_redacted = @()
            properties_requested = $props
            sensitive_attributes_blocked = @($Context.BlockedAttributes)
            limitations = @('Collector skipped because required module is unavailable.')
            collector_version = '1.0.0'
            data = $null
        }
    }
    $status = 'Collected'
    $warnings = @()
    $data = $null
    $examined = 0
    $emitted = 0
    $truncated = $false
    try {
        $pp = Get-ADDefaultDomainPasswordPolicy -ErrorAction Stop
        $examined = 1
        $emitted = 1
        $data = @{ password_policies = @([pscustomobject]@{ name = 'Default Domain Policy'; min_password_length = [int]$pp.MinPasswordLength; password_history_count = [int]$pp.PasswordHistoryCount; complexity_enabled = [bool]$pp.ComplexityEnabled; lockout_threshold = [int]$pp.LockoutThreshold; lockout_duration_minutes = [int]$pp.LockoutDuration.TotalMinutes }) }
        try {
            $fgpp = @(Get-ADFineGrainedPasswordPolicy -Filter * -ErrorAction Stop | Select-Object -First $Context.MaxObjects)
            $examined += $fgpp.Count
            $emitted += $fgpp.Count
            $data['fine_grained_password_policies'] = @($fgpp | ForEach-Object { [pscustomobject]@{ name = [string]$_.Name; min_password_length = [int]$_.MinPasswordLength } })
            if ($fgpp.Count -ge $Context.MaxObjects) { $truncated = $true; $warnings += 'Fine-grained password policy enumeration truncated.' }
        } catch {
            $warnings += 'Fine-grained password policies unavailable or not readable.'
        }

    } catch {
        $status = 'Error'
        $warnings += 'Collector error (details redacted).'
    }
    return [pscustomobject]@{
        collector_id = 'password-policies'
        category = 'live'
        status = $status
        started_at_utc = $started.ToString('o')
        completed_at_utc = [datetime]::UtcNow.ToString('o')
        duration_ms = [int]([datetime]::UtcNow - $started).TotalMilliseconds
        source_mode = 'Live'
        module_required = $moduleRequired
        module_available = $true
        objects_examined = $examined
        records_emitted = $emitted
        truncated = $truncated
        warnings = $warnings
        errors_redacted = @()
        properties_requested = $props
        sensitive_attributes_blocked = @($Context.BlockedAttributes)
        limitations = @('Read-only. Does not retrieve passwords, LAPS passwords, gMSA managed-password blobs, or hashes. Does not follow external trusts.')
        collector_version = '1.0.0'
        data = $data
    }
}
