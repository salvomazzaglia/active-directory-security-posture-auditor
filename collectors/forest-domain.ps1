function Invoke-ADSPCollector_forest_domain {
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
            collector_id = 'forest-domain'
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
        $forest = Get-ADForest -ErrorAction Stop
        $domain = Get-ADDomain -Identity $Context.Domain -ErrorAction Stop
        $examined = 2
        $emitted = 2
        $data = @{
            forest = [pscustomobject]@{ name = $forest.Name; functional_level = [string]$forest.ForestMode; recycle_bin_enabled = [bool]$forest.RecycleBinEnabled; schema_version = $null }
            domains = @([pscustomobject]@{ dns_name = $domain.DNSRoot; netbios_name = $domain.NetBIOSName; functional_level = [string]$domain.DomainMode; machine_account_quota = $null; sid = [string]$domain.DomainSID })
        }

    } catch {
        $status = 'Error'
        $warnings += 'Collector error (details redacted).'
    }
    return [pscustomobject]@{
        collector_id = 'forest-domain'
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
