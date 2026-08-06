function Invoke-ADSPCollector_trusts {
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
            collector_id = 'trusts'
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
        $trusts = @(Get-ADTrust -Filter * -ErrorAction Stop | Select-Object -First $Context.MaxObjects)
        $examined = $trusts.Count
        $emitted = $trusts.Count
        if ($trusts.Count -ge $Context.MaxObjects) { $truncated = $true; $warnings += 'Trust enumeration truncated.' }
        $data = @{ trusts = @($trusts | ForEach-Object {
            [pscustomobject]@{ target = [string]$_.Target; direction = [string]$_.Direction; trust_type = [string]$_.TrustType; sid_filtering = $null; selective_authentication = $null; tgt_delegation_enabled = $null; metadata_incomplete = $true; unresolved = $false; stale = $false; direction_unexpected = $false; transitive = $null; expands_exposure = $false; sid_history_risk = $false }
        }) }
        $warnings += 'Trusted domains are not queried automatically.'

    } catch {
        $status = 'Error'
        $warnings += 'Collector error (details redacted).'
    }
    return [pscustomobject]@{
        collector_id = 'trusts'
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
