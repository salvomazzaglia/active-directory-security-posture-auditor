function Get-ADSPCollectionPlan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Domain,
        [ValidateSet('Minimal','Standard','Extended')]$CollectionProfile = 'Standard'
    )
    # Never imports ActiveDirectory or queries a domain.
    $profiles = Get-Content -LiteralPath (Join-Path $script:ADSPRepoRoot 'config/collection-profiles.json') -Raw | ConvertFrom-Json
    $ids = @($profiles.profiles.$CollectionProfile.collectors)
    $blocked = Get-ADSPBlockedAttributeList
    $plan = [pscustomobject]@{
        domain = $Domain
        collection_profile = $CollectionProfile
        collectors = foreach ($id in $ids) {
            [pscustomobject]@{
                collector_id = $id
                module_required = $(if ($id -match 'gpo') { 'GroupPolicy' } elseif ($id -match 'laps') { 'ActiveDirectory' } else { 'ActiveDirectory' })
                object_classes = @('user','group','computer','domainDNS','trustedDomain')
                properties_requested_note = 'Allowlisted properties only; never -Properties *'
                sensitive_attributes_blocked = $blocked
            }
        }
        optional_collectors = @($profiles.profiles.Extended.collectors | Where-Object { $_ -notin $ids })
        limits = @{ max_objects = 50000; max_membership_depth = 8 }
        sensitivity_warnings = @(
            'Live collection performs read-only directory queries but still accesses sensitive identity and infrastructure metadata.',
            'Use only with explicit authorization.',
            'This plan does not query Active Directory.'
        )
        executes_query = $false
    }
    return $plan
}
