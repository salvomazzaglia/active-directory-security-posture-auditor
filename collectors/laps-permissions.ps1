function Invoke-ADSPCollector_laps_permissions {
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
            collector_id = 'laps-permissions'
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
    try {
        switch ('laps-permissions') {
            'forest-domain' {
                $forest = Get-ADForest -ErrorAction Stop
                $domain = Get-ADDomain -Identity $Context.Domain -ErrorAction Stop
                $data = @{
                    forest = [pscustomobject]@{ name = $forest.Name; functional_level = [string]$forest.ForestMode; recycle_bin_enabled = [bool]$forest.RecycleBinEnabled; schema_version = $null }
                    domains = @([pscustomobject]@{ dns_name = $domain.DNSRoot; netbios_name = $domain.NetBIOSName; functional_level = [string]$domain.DomainMode; machine_account_quota = $null; sid = [string]$domain.DomainSID })
                }
            }
            'password-policies' {
                $pp = Get-ADDefaultDomainPasswordPolicy -ErrorAction Stop
                $data = @{ password_policies = @([pscustomobject]@{ name = 'Default Domain Policy'; min_password_length = [int]$pp.MinPasswordLength; password_history_count = [int]$pp.PasswordHistoryCount; complexity_enabled = [bool]$pp.ComplexityEnabled; lockout_threshold = [int]$pp.LockoutThreshold; lockout_duration_minutes = [int]$pp.LockoutDuration.TotalMinutes }) }
            }
            'trusts' {
                $trusts = @(Get-ADTrust -Filter * -ErrorAction Stop | Select-Object -First $Context.MaxObjects)
                $data = @{ trusts = @($trusts | ForEach-Object { [pscustomobject]@{ target = [string]$_.Target; direction = [string]$_.Direction; trust_type = [string]$_.TrustType; sid_filtering = $null; selective_authentication = $null; tgt_delegation_enabled = $null; metadata_incomplete = $true; unresolved = $false; stale = $false; direction_unexpected = $false; transitive = $null; expands_exposure = $false; sid_history_risk = $false } }) }
            }
            default {
                $status = 'Partial'
                $warnings += 'Collector framework ready; object hydration depends on directory connectivity and profile.'
            }
        }
    } catch {
        $status = 'Error'
        $warnings += 'Collector error (details redacted).'
    }
    return [pscustomobject]@{
        collector_id = 'laps-permissions'
        category = 'live'
        status = $status
        started_at_utc = $started.ToString('o')
        completed_at_utc = [datetime]::UtcNow.ToString('o')
        duration_ms = [int]([datetime]::UtcNow - $started).TotalMilliseconds
        source_mode = 'Live'
        module_required = $moduleRequired
        module_available = $true
        objects_examined = 0
        records_emitted = 0
        truncated = $false
        warnings = $warnings
        errors_redacted = @()
        properties_requested = $props
        sensitive_attributes_blocked = @($Context.BlockedAttributes)
        limitations = @('Read-only. Does not retrieve passwords, LAPS passwords, gMSA managed-password blobs, or hashes. Does not follow external trusts.')
        collector_version = '1.0.0'
        data = $data
    }
}
