function Invoke-ADSPCollector {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$CollectorId,
        [Parameter(Mandatory)][string]$Domain,
        [switch]$ActiveDirectoryAvailable,
        [switch]$GroupPolicyAvailable
    )
    $allowed = @(
        'forest-domain','password-policies','users','groups','privileged-membership','computers','domain-controllers',
        'service-accounts','gmsa-metadata','kerberos-metadata','delegation','trusts','authentication-policies',
        'laps-metadata','laps-permissions','critical-object-acls','gpo-metadata','gpo-security-settings'
    )
    if ($allowed -notcontains $CollectorId) { throw "Collector not allowlisted: $CollectorId" }
    $scriptPath = Join-Path $script:ADSPRepoRoot ("collectors/{0}.ps1" -f $CollectorId)
    if (-not (Test-Path -LiteralPath $scriptPath)) { throw "Collector script missing: $CollectorId" }
    # Dot-source only repository-maintained allowlisted file (not user-provided path)
    . $scriptPath
    $fn = Get-Command -Name ("Invoke-ADSPCollector_{0}" -f ($CollectorId -replace '-','_')) -ErrorAction SilentlyContinue
    if (-not $fn) {
        return [pscustomobject]@{
            collector_id=$CollectorId; category='unknown'; status='Error'; started_at_utc=[datetime]::UtcNow.ToString('o'); completed_at_utc=[datetime]::UtcNow.ToString('o'); duration_ms=0; source_mode='Live'; module_required='ActiveDirectory'; module_available=[bool]$ActiveDirectoryAvailable; objects_examined=0; records_emitted=0; truncated=$false; warnings=@(); errors_redacted=@('collector function missing'); properties_requested=@(); sensitive_attributes_blocked=@(Get-ADSPBlockedAttributeList); limitations=@(); collector_version='1.0.0'; data=$null
        }
    }
    $ctx = @{
        Domain = $Domain
        ActiveDirectoryAvailable = [bool]$ActiveDirectoryAvailable
        GroupPolicyAvailable = [bool]$GroupPolicyAvailable
        BlockedAttributes = @(Get-ADSPBlockedAttributeList)
        MaxObjects = 50000
    }
    return & $fn -Context $ctx
}
