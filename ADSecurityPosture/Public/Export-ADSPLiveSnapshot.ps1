function Export-ADSPLiveSnapshot {
    [CmdletBinding()]
    param(
        [switch]$AcknowledgeLiveDirectoryQuery,
        [switch]$AuthorizedUse,
        [Parameter(Mandatory)][string]$Domain,
        [Parameter(Mandatory)][ValidateSet('Minimal','Standard','Extended')]$CollectionProfile,
        [Parameter(Mandatory)][string]$OutputDirectory,
        [string]$OperatorLabel = $env:USERNAME,
        [string]$AuthorizationReference = ''
    )
    if (-not $AcknowledgeLiveDirectoryQuery -or -not $AuthorizedUse) {
        throw 'Live collection requires -AcknowledgeLiveDirectoryQuery and -AuthorizedUse. Refusing to continue.'
    }
    if ([string]::IsNullOrWhiteSpace($Domain)) { throw 'Domain is required.' }
    if ([string]::IsNullOrWhiteSpace($OutputDirectory)) { throw 'OutputDirectory is required.' }
    if ([string]::IsNullOrWhiteSpace($CollectionProfile)) { throw 'CollectionProfile is required.' }

    Write-ADSPConsole -Level Warn -Message ("Current Windows identity: {0}" -f [System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
    Write-ADSPConsole -Level Warn -Message ("Target domain: {0}" -f $Domain)
    Write-ADSPConsole -Level Warn -Message 'Raw snapshots can contain sensitive identity and infrastructure metadata.'

    $out = Assert-ADSPSafePath -Path $OutputDirectory -IsOutput -AllowAbsolute
    if (Test-Path -LiteralPath $out) {
        $children = @(Get-ChildItem -LiteralPath $out -Force -ErrorAction SilentlyContinue)
        if ($children.Count -gt 0) { throw "Refuse overwrite of non-empty output directory: $out" }
    } else {
        New-Item -ItemType Directory -Path $out -Force | Out-Null
    }

    $adAvailable = [bool](Get-Module -ListAvailable -Name ActiveDirectory)
    $gpAvailable = [bool](Get-Module -ListAvailable -Name GroupPolicy)
    $profiles = Get-Content -LiteralPath (Join-Path $script:ADSPRepoRoot 'config/collection-profiles.json') -Raw | ConvertFrom-Json
    $ids = @($profiles.profiles.$CollectionProfile.collectors)
    $collectors = @()
    foreach ($id in $ids) {
        $result = Invoke-ADSPCollector -CollectorId $id -Domain $Domain -ActiveDirectoryAvailable:$adAvailable -GroupPolicyAvailable:$gpAvailable
        $collectors += $result
    }

    # Live collection assembles a snapshot shell; when AD module absent, mark Unavailable and do not fabricate domain secrets.
    $snapshot = [ordered]@{
        schema_version='1.0.0'
        tool_name='active-directory-security-posture-auditor'
        tool_version='1.0.0'
        snapshot_id=[guid]::NewGuid().ToString()
        generated_at_utc=[datetime]::UtcNow.ToString('o')
        source_mode='Live'
        synthetic=$false
        collection_profile=$CollectionProfile
        operator_label=$OperatorLabel
        authorization_reference=$AuthorizationReference
        target_domain_label=$Domain
        target_forest_label=$Domain
        privacy_notice='Raw live snapshots contain sensitive identity metadata. Protect and retain per authorization.'
        collector_status_counts=@{}
        collectors=$collectors
        forest=$null
        domains=@()
        password_policies=@()
        fine_grained_password_policies=@()
        users=@(); groups=@(); group_memberships=@(); privileged_memberships=@()
        computers=@(); domain_controllers=@(); service_accounts=@(); gmsa_accounts=@(); spns=@()
        kerberos_metadata=$null; delegation_metadata=@(); authentication_policies=@(); authentication_policy_silos=@()
        trusts=@(); laps_metadata=$null; laps_permission_metadata=@(); gpo_metadata=@(); gpo_security_settings=@(); critical_object_acls=@()
        limitations=@('Live collectors use read-only allowlisted cmdlets only when modules are available.')
        excluded_sensitive_attributes=@(Get-ADSPBlockedAttributeList)
        snapshot_hash=''
        modules_available=@{ ActiveDirectory=$adAvailable; GroupPolicy=$gpAvailable }
    }

    # Merge collected records where present
    foreach ($c in $collectors) {
        if ($c.data) {
            foreach ($prop in $c.data.PSObject.Properties.Name) {
                if ($snapshot.Contains($prop)) { $snapshot[$prop] = $c.data.$prop }
            }
        }
    }
    $statusCounts = @{ Collected=0; Partial=0; Unavailable=0; Error=0; Skipped=0 }
    foreach ($c in $collectors) {
        if ($statusCounts.ContainsKey($c.status)) { $statusCounts[$c.status]++ }
    }
    $snapshot.collector_status_counts = $statusCounts
    $obj = [pscustomobject]$snapshot
    $obj.snapshot_hash = Get-ADSPSnapshotHash -Snapshot $obj
    $path = Join-Path $out 'snapshot.json'
    [IO.File]::WriteAllText($path, (ConvertTo-ADSPCanonicalJson -InputObject $obj), [Text.UTF8Encoding]::new($false))
    try {
        if ($IsWindows -or $env:OS -match 'Windows') {
            icacls $out /inheritance:r | Out-Null
        }
    } catch {}
    Write-ADSPConsole -Level Warn -Message 'Sensitivity warning: protect this snapshot. It is not anonymized.'
    return $obj
}
