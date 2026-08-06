function New-ADSPSyntheticSnapshot {
    [CmdletBinding()]
    param(
        [string]$OutputDirectory,
        [string]$OperatorLabel = 'synthetic-operator'
    )
    $sidBase = 'S-1-5-21-1000000001-1000000002-1000000003'
    $now = [datetime]::Parse('2026-01-15T12:00:00Z').ToUniversalTime()
    $guid = {
        param([int]$n)
        return [guid]::Parse(('00000000-0000-4000-8000-{0:D12}' -f $n)).ToString()
    }

    $users = @(
        [pscustomobject]@{ object_guid=& $guid 1; object_sid="$sidBase-500"; sam_account_name='Administrator'; object_class='user'; enabled=$true; password_age_days=400; password_never_expires=$false; password_not_required=$false; reversible_encryption=$false; does_not_require_preauth=$false; use_des_key_only=$false; legacy_encryption_only=$false; sid_history=@(); inactive_days=1; never_logged_on=$false; age_days=2000; account_expired=$false; cannot_change_password=$false; user_principal_name='Administrator@corp.example.invalid'; is_service_account=$false; is_privileged=$true; admin_count=1; account_not_delegated=$true; in_protected_users=$false; spns=@(); trusted_for_delegation=$false; trusted_to_auth_for_delegation=$false; credential_clue_detected=$false; description_admin_heuristic=$false; naming_suggests_temporary=$false; account_expires=$null; no_modern_kerberos_etypes=$false; in_sensitive_group=$true; lacks_aes=$false }
        [pscustomobject]@{ object_guid=& $guid 2; object_sid="$sidBase-501"; sam_account_name='Guest'; object_class='user'; enabled=$true; password_age_days=0; password_never_expires=$true; password_not_required=$true; reversible_encryption=$false; does_not_require_preauth=$false; use_des_key_only=$false; legacy_encryption_only=$false; sid_history=@(); inactive_days=999; never_logged_on=$true; age_days=2000; account_expired=$false; cannot_change_password=$true; user_principal_name=''; is_service_account=$false; is_privileged=$false; admin_count=0; account_not_delegated=$false; in_protected_users=$false; spns=@(); trusted_for_delegation=$false; trusted_to_auth_for_delegation=$false; credential_clue_detected=$false; description_admin_heuristic=$false; naming_suggests_temporary=$false; account_expires=$null; no_modern_kerberos_etypes=$false; in_sensitive_group=$false; lacks_aes=$false }
        [pscustomobject]@{ object_guid=& $guid 3; object_sid="$sidBase-502"; sam_account_name='krbtgt'; object_class='user'; enabled=$false; password_age_days=500; password_never_expires=$false; password_not_required=$false; reversible_encryption=$false; does_not_require_preauth=$false; use_des_key_only=$false; legacy_encryption_only=$false; sid_history=@(); inactive_days=0; never_logged_on=$false; age_days=2000; account_expired=$false; cannot_change_password=$true; user_principal_name=''; is_service_account=$false; is_privileged=$true; admin_count=0; account_not_delegated=$true; in_protected_users=$false; spns=@(); trusted_for_delegation=$false; trusted_to_auth_for_delegation=$false; credential_clue_detected=$false; description_admin_heuristic=$false; naming_suggests_temporary=$false; account_expires=$null; no_modern_kerberos_etypes=$false; in_sensitive_group=$false; lacks_aes=$false }
        [pscustomobject]@{ object_guid=& $guid 10; object_sid="$sidBase-1100"; sam_account_name='synthetic-admin'; object_class='user'; enabled=$true; password_age_days=120; password_never_expires=$false; password_not_required=$false; reversible_encryption=$false; does_not_require_preauth=$false; use_des_key_only=$false; legacy_encryption_only=$false; sid_history=@(); inactive_days=2; never_logged_on=$false; age_days=400; account_expired=$false; cannot_change_password=$false; user_principal_name='synthetic-admin@corp.example.invalid'; is_service_account=$false; is_privileged=$true; admin_count=1; account_not_delegated=$false; in_protected_users=$false; spns=@('HTTP/synthetic-admin.corp.example.invalid'); trusted_for_delegation=$true; trusted_to_auth_for_delegation=$false; credential_clue_detected=$false; description_admin_heuristic=$true; naming_suggests_temporary=$false; account_expires=$null; no_modern_kerberos_etypes=$false; in_sensitive_group=$true; lacks_aes=$false; protected_membership=$true }
        [pscustomobject]@{ object_guid=& $guid 11; object_sid="$sidBase-1101"; sam_account_name='synthetic-tier0-admin'; object_class='user'; enabled=$true; password_age_days=30; password_never_expires=$false; password_not_required=$false; reversible_encryption=$false; does_not_require_preauth=$false; use_des_key_only=$false; legacy_encryption_only=$false; sid_history=@(); inactive_days=1; never_logged_on=$false; age_days=200; account_expired=$false; cannot_change_password=$false; user_principal_name='synthetic-tier0-admin@corp.example.invalid'; is_service_account=$false; is_privileged=$true; admin_count=1; account_not_delegated=$true; in_protected_users=$true; spns=@(); trusted_for_delegation=$false; trusted_to_auth_for_delegation=$false; credential_clue_detected=$false; description_admin_heuristic=$false; naming_suggests_temporary=$false; account_expires=$null; no_modern_kerberos_etypes=$false; in_sensitive_group=$true; lacks_aes=$true; protected_membership=$true }
        [pscustomobject]@{ object_guid=& $guid 12; object_sid="$sidBase-1102"; sam_account_name='synthetic-helpdesk'; object_class='user'; enabled=$true; password_age_days=60; password_never_expires=$false; password_not_required=$false; reversible_encryption=$false; does_not_require_preauth=$false; use_des_key_only=$false; legacy_encryption_only=$false; sid_history=@(); inactive_days=5; never_logged_on=$false; age_days=300; account_expired=$false; cannot_change_password=$false; user_principal_name='synthetic-helpdesk@corp.example.invalid'; is_service_account=$false; is_privileged=$false; admin_count=0; account_not_delegated=$false; in_protected_users=$false; spns=@(); trusted_for_delegation=$false; trusted_to_auth_for_delegation=$false; credential_clue_detected=$false; description_admin_heuristic=$false; naming_suggests_temporary=$false; account_expires=$null; no_modern_kerberos_etypes=$false; in_sensitive_group=$false; lacks_aes=$false }
        [pscustomobject]@{ object_guid=& $guid 13; object_sid="$sidBase-1103"; sam_account_name='synthetic-user'; object_class='user'; enabled=$true; password_age_days=40; password_never_expires=$false; password_not_required=$false; reversible_encryption=$false; does_not_require_preauth=$false; use_des_key_only=$false; legacy_encryption_only=$false; sid_history=@(); inactive_days=3; never_logged_on=$false; age_days=100; account_expired=$false; cannot_change_password=$false; user_principal_name='synthetic-user@corp.example.invalid'; is_service_account=$false; is_privileged=$false; admin_count=0; account_not_delegated=$false; in_protected_users=$false; spns=@(); trusted_for_delegation=$false; trusted_to_auth_for_delegation=$false; credential_clue_detected=$false; description_admin_heuristic=$false; naming_suggests_temporary=$false; account_expires=$null; no_modern_kerberos_etypes=$false; in_sensitive_group=$false; lacks_aes=$false }
        [pscustomobject]@{ object_guid=& $guid 14; object_sid="$sidBase-1104"; sam_account_name='synthetic-disabled-user'; object_class='user'; enabled=$false; password_age_days=200; password_never_expires=$false; password_not_required=$false; reversible_encryption=$false; does_not_require_preauth=$false; use_des_key_only=$false; legacy_encryption_only=$false; sid_history=@(); inactive_days=200; never_logged_on=$false; age_days=400; account_expired=$false; cannot_change_password=$false; user_principal_name='synthetic-disabled-user@corp.example.invalid'; is_service_account=$false; is_privileged=$true; admin_count=1; account_not_delegated=$false; in_protected_users=$false; spns=@(); trusted_for_delegation=$false; trusted_to_auth_for_delegation=$false; credential_clue_detected=$false; description_admin_heuristic=$false; naming_suggests_temporary=$false; account_expires=$null; no_modern_kerberos_etypes=$false; in_sensitive_group=$true; lacks_aes=$false; protected_membership=$false }
        [pscustomobject]@{ object_guid=& $guid 15; object_sid="$sidBase-1105"; sam_account_name='synthetic-stale-user'; object_class='user'; enabled=$true; password_age_days=400; password_never_expires=$false; password_not_required=$false; reversible_encryption=$false; does_not_require_preauth=$false; use_des_key_only=$false; legacy_encryption_only=$false; sid_history=@("$sidBase-9999"); inactive_days=200; never_logged_on=$false; age_days=500; account_expired=$true; cannot_change_password=$false; user_principal_name='synthetic-stale-user@corp.example.invalid'; is_service_account=$false; is_privileged=$true; admin_count=1; account_not_delegated=$false; in_protected_users=$false; spns=@(); trusted_for_delegation=$false; trusted_to_auth_for_delegation=$false; credential_clue_detected=$true; description_admin_heuristic=$false; naming_suggests_temporary=$true; account_expires=$null; no_modern_kerberos_etypes=$false; in_sensitive_group=$true; lacks_aes=$false; protected_membership=$true }
        [pscustomobject]@{ object_guid=& $guid 16; object_sid="$sidBase-1106"; sam_account_name='synthetic-service'; object_class='user'; enabled=$true; password_age_days=400; password_never_expires=$true; password_not_required=$false; reversible_encryption=$true; does_not_require_preauth=$true; use_des_key_only=$true; legacy_encryption_only=$true; sid_history=@(); inactive_days=100; never_logged_on=$false; age_days=600; account_expired=$false; cannot_change_password=$true; user_principal_name='synthetic-service@corp.example.invalid'; is_service_account=$true; is_privileged=$true; admin_count=0; account_not_delegated=$false; in_protected_users=$true; spns=@('MSSQLSvc/synthetic-srv01.corp.example.invalid:1433'); trusted_for_delegation=$true; trusted_to_auth_for_delegation=$true; credential_clue_detected=$true; description_admin_heuristic=$false; naming_suggests_temporary=$false; account_expires=$null; no_modern_kerberos_etypes=$true; in_sensitive_group=$true; lacks_aes=$true; owner_label=$null }
        [pscustomobject]@{ object_guid=& $guid 17; object_sid="$sidBase-1107"; sam_account_name='synthetic-sql-service'; object_class='user'; enabled=$true; password_age_days=200; password_never_expires=$true; password_not_required=$false; reversible_encryption=$false; does_not_require_preauth=$false; use_des_key_only=$false; legacy_encryption_only=$false; sid_history=@(); inactive_days=10; never_logged_on=$false; age_days=300; account_expired=$false; cannot_change_password=$false; user_principal_name='synthetic-sql-service@corp.example.invalid'; is_service_account=$true; is_privileged=$false; admin_count=0; account_not_delegated=$false; in_protected_users=$false; spns=@('MSSQLSvc/synthetic-srv01.corp.example.invalid:1433'); trusted_for_delegation=$false; trusted_to_auth_for_delegation=$false; credential_clue_detected=$false; description_admin_heuristic=$false; naming_suggests_temporary=$false; account_expires=$null; no_modern_kerberos_etypes=$false; in_sensitive_group=$false; lacks_aes=$false; owner_label='synthetic-owner' }
    )

    $groups = @(
        [pscustomobject]@{ object_guid=& $guid 50; object_sid="$sidBase-512"; sam_account_name='Domain Admins'; object_class='group'; tier='highest' }
        [pscustomobject]@{ object_guid=& $guid 51; object_sid="$sidBase-519"; sam_account_name='Enterprise Admins'; object_class='group'; tier='highest' }
        [pscustomobject]@{ object_guid=& $guid 52; object_sid='S-1-5-32-544'; sam_account_name='Administrators'; object_class='group'; tier='highest' }
        [pscustomobject]@{ object_guid=& $guid 53; object_sid="$sidBase-1108"; sam_account_name='synthetic-nested-admins'; object_class='group'; tier='nested' }
        [pscustomobject]@{ object_guid=& $guid 54; object_sid="$sidBase-1109"; sam_account_name='synthetic-cycle-a'; object_class='group'; tier='nested' }
        [pscustomobject]@{ object_guid=& $guid 55; object_sid="$sidBase-1110"; sam_account_name='synthetic-cycle-b'; object_class='group'; tier='nested' }
        [pscustomobject]@{ object_guid=& $guid 56; object_sid='S-1-5-32-548'; sam_account_name='Account Operators'; object_class='group'; tier='operator' }
        [pscustomobject]@{ object_guid=& $guid 57; object_sid="$sidBase-520"; sam_account_name='Group Policy Creator Owners'; object_class='group'; tier='operator' }
        [pscustomobject]@{ object_guid=& $guid 58; object_sid="$sidBase-525"; sam_account_name='Protected Users'; object_class='group'; tier='protective' }
    )

    $memberships = @(
        [pscustomobject]@{ group_sam='Domain Admins'; member_sam='synthetic-admin'; member_guid=(& $guid 10); member_class='user'; membership_type='Direct'; group_tier='highest'; path_depth=1; cycle_detected=$false; unresolved_sid=$false; protected_membership=$true; member_sid="$sidBase-1100" }
        [pscustomobject]@{ group_sam='Domain Admins'; member_sam='synthetic-tier0-admin'; member_guid=(& $guid 11); member_class='user'; membership_type='Direct'; group_tier='highest'; path_depth=1; cycle_detected=$false; unresolved_sid=$false; protected_membership=$true; member_sid="$sidBase-1101" }
        [pscustomobject]@{ group_sam='Domain Admins'; member_sam='synthetic-disabled-user'; member_guid=(& $guid 14); member_class='user'; membership_type='Direct'; group_tier='highest'; path_depth=1; cycle_detected=$false; unresolved_sid=$false; protected_membership=$false; member_sid="$sidBase-1104" }
        [pscustomobject]@{ group_sam='Domain Admins'; member_sam='synthetic-stale-user'; member_guid=(& $guid 15); member_class='user'; membership_type='Direct'; group_tier='highest'; path_depth=1; cycle_detected=$false; unresolved_sid=$false; protected_membership=$true; member_sid="$sidBase-1105" }
        [pscustomobject]@{ group_sam='Domain Admins'; member_sam='synthetic-service'; member_guid=(& $guid 16); member_class='service'; membership_type='Direct'; group_tier='highest'; path_depth=1; cycle_detected=$false; unresolved_sid=$false; protected_membership=$false; member_sid="$sidBase-1106" }
        [pscustomobject]@{ group_sam='Domain Admins'; member_sam='synthetic-nested-admins'; member_guid=(& $guid 53); member_class='group'; membership_type='Direct'; group_tier='highest'; path_depth=1; cycle_detected=$false; unresolved_sid=$false; protected_membership=$false; member_sid="$sidBase-1108" }
        [pscustomobject]@{ group_sam='synthetic-nested-admins'; member_sam='synthetic-helpdesk'; member_guid=(& $guid 12); member_class='user'; membership_type='Transitive'; group_tier='highest'; path_depth=2; cycle_detected=$false; unresolved_sid=$false; protected_membership=$false; member_sid="$sidBase-1102" }
        [pscustomobject]@{ group_sam='Domain Admins'; member_sam='synthetic-helpdesk'; member_guid=(& $guid 12); member_class='user'; membership_type='Transitive'; group_tier='highest'; path_depth=2; cycle_detected=$false; unresolved_sid=$false; protected_membership=$false; member_sid="$sidBase-1102" }
        [pscustomobject]@{ group_sam='synthetic-cycle-a'; member_sam='synthetic-cycle-b'; member_guid=(& $guid 55); member_class='group'; membership_type='Direct'; group_tier='nested'; path_depth=1; cycle_detected=$true; unresolved_sid=$false; protected_membership=$false; member_sid="$sidBase-1110" }
        [pscustomobject]@{ group_sam='synthetic-cycle-b'; member_sam='synthetic-cycle-a'; member_guid=(& $guid 54); member_class='group'; membership_type='Direct'; group_tier='nested'; path_depth=1; cycle_detected=$true; unresolved_sid=$false; protected_membership=$false; member_sid="$sidBase-1109" }
        [pscustomobject]@{ group_sam='Domain Admins'; member_sam='synthetic-cycle-a'; member_guid=(& $guid 54); member_class='group'; membership_type='Direct'; group_tier='highest'; path_depth=1; cycle_detected=$true; unresolved_sid=$false; protected_membership=$false; member_sid="$sidBase-1109" }
        [pscustomobject]@{ group_sam='Account Operators'; member_sam='synthetic-helpdesk'; member_guid=(& $guid 12); member_class='user'; membership_type='Direct'; group_tier='operator'; path_depth=1; cycle_detected=$false; unresolved_sid=$false; protected_membership=$false; member_sid="$sidBase-1102" }
        [pscustomobject]@{ group_sam='Group Policy Creator Owners'; member_sam='synthetic-admin'; member_guid=(& $guid 10); member_class='user'; membership_type='Direct'; group_tier='operator'; path_depth=1; cycle_detected=$false; unresolved_sid=$false; protected_membership=$false; member_sid="$sidBase-1100" }
        [pscustomobject]@{ group_sam='Group Policy Creator Owners'; member_sam='synthetic-helpdesk'; member_guid=(& $guid 12); member_class='user'; membership_type='Direct'; group_tier='operator'; path_depth=1; cycle_detected=$false; unresolved_sid=$false; protected_membership=$false; member_sid="$sidBase-1102" }
        [pscustomobject]@{ group_sam='Protected Users'; member_sam='synthetic-tier0-admin'; member_guid=(& $guid 11); member_class='user'; membership_type='Direct'; group_tier='protective'; path_depth=1; cycle_detected=$false; unresolved_sid=$false; protected_membership=$true; member_sid="$sidBase-1101" }
        [pscustomobject]@{ group_sam='Protected Users'; member_sam='synthetic-service'; member_guid=(& $guid 16); member_class='service'; membership_type='Direct'; group_tier='protective'; path_depth=1; cycle_detected=$false; unresolved_sid=$false; protected_membership=$false; member_sid="$sidBase-1106" }
        [pscustomobject]@{ group_sam='Domain Admins'; member_sam='S-1-5-21-1000000001-1000000002-1000000003-9998'; member_guid=$null; member_class='foreignSecurityPrincipal'; membership_type='Direct'; group_tier='highest'; path_depth=1; cycle_detected=$false; unresolved_sid=$true; protected_membership=$false; member_sid="$sidBase-9998" }
        [pscustomobject]@{ group_sam='Domain Admins'; member_sam='SYNTHETIC-OLD01$'; member_guid=(& $guid 72); member_class='computer'; membership_type='Direct'; group_tier='highest'; path_depth=1; cycle_detected=$false; unresolved_sid=$false; protected_membership=$false; member_sid="$sidBase-1205" }
    )

    $computers = @(
        [pscustomobject]@{ object_guid=& $guid 70; object_sid="$sidBase-1201"; sam_account_name='SYNTHETIC-DC01$'; dns_hostname='SYNTHETIC-DC01.corp.example.invalid'; enabled=$true; is_domain_controller=$true; inactive_days=1; operating_system='Windows Server 2022 Standard'; unexpected_delegation=$false; unexpected_spn_pattern=$false; is_rodc=$false; prp_unavailable=$false; prp_overly_broad=$false; rbcd_present=$false; laps_expiration_utc=$null; laps_expiration_anomaly=$false; laps_eligible=$false; in_sensitive_group=$false; distinguished_name='CN=SYNTHETIC-DC01,OU=Domain Controllers,DC=corp,DC=example,DC=invalid'; password_age_days=20; protected_from_accidental_deletion=$true }
        [pscustomobject]@{ object_guid=& $guid 71; object_sid="$sidBase-1202"; sam_account_name='SYNTHETIC-DC02$'; dns_hostname='SYNTHETIC-DC02.corp.example.invalid'; enabled=$true; is_domain_controller=$true; inactive_days=1; operating_system='Windows Server 2022 Standard'; unexpected_delegation=$false; unexpected_spn_pattern=$false; is_rodc=$false; prp_unavailable=$false; prp_overly_broad=$false; rbcd_present=$false; laps_expiration_utc=$null; laps_expiration_anomaly=$false; laps_eligible=$false; in_sensitive_group=$false; distinguished_name='CN=SYNTHETIC-DC02,CN=Computers,DC=corp,DC=example,DC=invalid'; password_age_days=80; protected_from_accidental_deletion=$false }
        [pscustomobject]@{ object_guid=& $guid 72; object_sid="$sidBase-1205"; sam_account_name='SYNTHETIC-OLD01$'; dns_hostname='SYNTHETIC-OLD01.corp.example.invalid'; enabled=$true; is_domain_controller=$false; inactive_days=400; operating_system='Windows Server 2008 R2 Enterprise'; unexpected_delegation=$true; unexpected_spn_pattern=$true; is_rodc=$false; prp_unavailable=$false; prp_overly_broad=$false; rbcd_present=$true; laps_expiration_utc=$null; laps_expiration_anomaly=$false; laps_eligible=$true; in_sensitive_group=$true; distinguished_name='CN=SYNTHETIC-OLD01,CN=Computers,DC=corp,DC=example,DC=invalid'; password_age_days=400; protected_from_accidental_deletion=$false; laps_expiration_overdue=$false; laps_expiration_far_future=$false }
        [pscustomobject]@{ object_guid=& $guid 73; object_sid="$sidBase-1203"; sam_account_name='SYNTHETIC-WS01$'; dns_hostname='SYNTHETIC-WS01.corp.example.invalid'; enabled=$true; is_domain_controller=$false; inactive_days=5; operating_system='Windows 11 Enterprise'; unexpected_delegation=$false; unexpected_spn_pattern=$false; is_rodc=$false; prp_unavailable=$false; prp_overly_broad=$false; rbcd_present=$false; laps_expiration_utc='2025-01-01T00:00:00Z'; laps_expiration_anomaly=$true; laps_eligible=$true; in_sensitive_group=$false; distinguished_name='CN=SYNTHETIC-WS01,CN=Computers,DC=corp,DC=example,DC=invalid'; password_age_days=30; protected_from_accidental_deletion=$false; laps_expiration_overdue=$true; laps_expiration_far_future=$false }
        [pscustomobject]@{ object_guid=& $guid 74; object_sid="$sidBase-1204"; sam_account_name='SYNTHETIC-SRV01$'; dns_hostname='SYNTHETIC-SRV01.corp.example.invalid'; enabled=$true; is_domain_controller=$false; inactive_days=2; operating_system='Windows Server 2022 Standard'; unexpected_delegation=$false; unexpected_spn_pattern=$false; is_rodc=$false; prp_unavailable=$false; prp_overly_broad=$false; rbcd_present=$false; laps_expiration_utc='2030-01-01T00:00:00Z'; laps_expiration_anomaly=$true; laps_eligible=$true; in_sensitive_group=$false; distinguished_name='CN=SYNTHETIC-SRV01,CN=Computers,DC=corp,DC=example,DC=invalid'; password_age_days=40; protected_from_accidental_deletion=$false; laps_expiration_overdue=$false; laps_expiration_far_future=$true }
    )

    $snapshot = [ordered]@{
        schema_version = '1.0.0'
        tool_name = 'active-directory-security-posture-auditor'
        tool_version = '1.0.0'
        snapshot_id = 'synth-00000000-0000-4000-8000-000000000001'
        generated_at_utc = $now.ToString('o')
        source_mode = 'Synthetic'
        synthetic = $true
        collection_profile = 'Extended'
        operator_label = $OperatorLabel
        authorization_reference = 'SYNTHETIC-DEMO'
        target_domain_label = 'corp.example.invalid'
        target_forest_label = 'corp.example.invalid'
        privacy_notice = 'SYNTHETIC DEMONSTRATION DATA. Raw snapshots can contain sensitive identity metadata.'
        collector_status_counts = @{ Collected = 18; Partial = 0; Unavailable = 0; Error = 0; Skipped = 0 }
        collectors = @()
        forest = [pscustomobject]@{ name='corp.example.invalid'; functional_level='Windows2016Forest'; recycle_bin_enabled=$false; schema_version=88 }
        domains = @([pscustomobject]@{ dns_name='corp.example.invalid'; netbios_name='SYNTHETIC'; functional_level='Windows2016Domain'; machine_account_quota=10; sid="$sidBase" })
        password_policies = @([pscustomobject]@{ name='Default Domain Policy'; min_password_length=8; password_history_count=12; complexity_enabled=$false; lockout_threshold=0; lockout_duration_minutes=5 })
        fine_grained_password_policies = @()
        users = $users
        groups = $groups
        group_memberships = $memberships
        privileged_memberships = $memberships
        computers = $computers
        domain_controllers = @($computers | Where-Object { $_.is_domain_controller })
        service_accounts = @($users | Where-Object { $_.is_service_account } | ForEach-Object {
            [pscustomobject]@{ object_guid=$_.object_guid; sam_account_name=$_.sam_account_name; enabled=$_.enabled; password_age_days=$_.password_age_days; password_never_expires=$_.password_never_expires; spns=$_.spns; is_privileged=$_.is_privileged; inactive_days=$_.inactive_days; trusted_for_delegation=$_.trusted_for_delegation; trusted_to_auth_for_delegation=$_.trusted_to_auth_for_delegation; lacks_aes=$_.lacks_aes; credential_clue_detected=$_.credential_clue_detected; owner_label=$_.owner_label; is_gmsa=$false }
        })
        gmsa_accounts = @([pscustomobject]@{ object_guid=(& $guid 18); sam_account_name='synthetic-web-gmsa$'; retrieval_principals=@('Domain Computers','Domain Admins'); retrieval_principals_broad=$true; is_privileged=$true })
        spns = @(
            [pscustomobject]@{ spn='MSSQLSvc/synthetic-srv01.corp.example.invalid:1433'; account_sam='synthetic-service' }
            [pscustomobject]@{ spn='MSSQLSvc/synthetic-srv01.corp.example.invalid:1433'; account_sam='synthetic-sql-service' }
            [pscustomobject]@{ spn='HTTP/synthetic-admin.corp.example.invalid'; account_sam='synthetic-admin' }
        )
        kerberos_metadata = [pscustomobject]@{ max_ticket_age_hours=20; max_renew_age_days=14 }
        delegation_metadata = @(
            [pscustomobject]@{ account_sam='SYNTHETIC-OLD01$'; unconstrained=$true; is_domain_controller=$false; sensitive=$false; constrained_high_impact=$false; protocol_transition=$false; rbcd_broad=$true; unresolved_target=$true; high_privilege_broad_scope=$true }
            [pscustomobject]@{ account_sam='synthetic-service'; unconstrained=$true; is_domain_controller=$false; sensitive=$true; constrained_high_impact=$true; protocol_transition=$true; rbcd_broad=$false; unresolved_target=$false; high_privilege_broad_scope=$true }
        )
        authentication_policies = @()
        authentication_policy_silos = @([pscustomobject]@{ name='synthetic-silo'; inconsistent_membership=$true })
        trusts = @(
            [pscustomobject]@{ target='partner.example.invalid'; direction='Bidirectional'; trust_type='External'; sid_filtering=$false; selective_authentication=$false; tgt_delegation_enabled=$true; metadata_incomplete=$true; unresolved=$false; stale=$true; direction_unexpected=$false; transitive=$true; expands_exposure=$true; sid_history_risk=$true }
        )
        laps_metadata = [pscustomobject]@{ windows_laps_schema_present=$true; legacy_laps_schema_present=$true; inconsistent_coexistence=$true }
        laps_permission_metadata = @(
            [pscustomobject]@{ principal='Authenticated Users'; broad_reader=$true; broad_reset=$true; reader_is_highest_privilege=$false }
            [pscustomobject]@{ principal='Domain Admins'; broad_reader=$true; broad_reset=$false; reader_is_highest_privilege=$true }
        )
        gpo_metadata = @(
            [pscustomobject]@{ display_name='Synthetic Default Domain Policy Export'; unexpected_owner=$false; unresolved_owner=$false; broad_edit_rights=$true; security_relevant=$true; linked=$true }
            [pscustomobject]@{ display_name='Synthetic Domain Controller Security Policy'; unexpected_owner=$true; unresolved_owner=$false; broad_edit_rights=$false; security_relevant=$true; linked=$true }
            [pscustomobject]@{ display_name='Synthetic Legacy Compatibility Policy'; unexpected_owner=$false; unresolved_owner=$true; broad_edit_rights=$false; security_relevant=$true; linked=$false }
        )
        gpo_security_settings = @(
            [pscustomobject]@{ gpo_name='Synthetic Domain Controller Security Policy'; setting_name='LDAPServerSigning'; value='None' }
            [pscustomobject]@{ gpo_name='Synthetic Domain Controller Security Policy'; setting_name='LDAPClientSigning'; value='None' }
            [pscustomobject]@{ gpo_name='Synthetic Domain Controller Security Policy'; setting_name='LDAPChannelBinding'; value='Never' }
            [pscustomobject]@{ gpo_name='Synthetic Legacy Compatibility Policy'; setting_name='LmCompatibilityLevel'; value=2 }
            [pscustomobject]@{ gpo_name='Synthetic Legacy Compatibility Policy'; setting_name='NoLMHash'; value='0' }
            [pscustomobject]@{ gpo_name='Synthetic Legacy Compatibility Policy'; setting_name='AnonymousSidTranslation'; value='Enabled' }
            [pscustomobject]@{ gpo_name='Synthetic Domain Controller Security Policy'; setting_name='RequireSignOrSeal'; value='Disabled' }
            [pscustomobject]@{ gpo_name='Synthetic Default Domain Policy Export'; setting_name='MinimumPasswordLength'; value=8 }
            [pscustomobject]@{ gpo_name='Synthetic Default Domain Policy Export'; setting_name='LockoutThreshold'; value=0 }
            [pscustomobject]@{ gpo_name='Synthetic Default Domain Policy Export'; setting_name='MaxTicketAge'; value=20 }
            [pscustomobject]@{ gpo_name='Synthetic Domain Controller Security Policy'; setting_name='AuditSubcategoryOverride'; value='Disabled' }
        )
        critical_object_acls = @(
            [pscustomobject]@{ object_id='domain-root'; principal='synthetic-helpdesk'; right='GenericAll'; unexpected=$true; dcsync_like=$false; modifies_privileged_group=$false; reset_privileged_password=$false; write_spn_privileged=$false; write_delegation_critical=$false; unexpected_owner=$false; unresolved_sid=$false; inherited_broad=$true; laps_read_broad=$false; laps_reset_broad=$false; create_computer_critical_ou=$false; create_user_privileged_ou=$false; unknown_object_guid=$false }
            [pscustomobject]@{ object_id='domain-root'; principal='synthetic-service'; right='WriteDacl'; unexpected=$true; dcsync_like=$false; modifies_privileged_group=$false; reset_privileged_password=$false; write_spn_privileged=$false; write_delegation_critical=$false; unexpected_owner=$false; unresolved_sid=$false; inherited_broad=$false; laps_read_broad=$false; laps_reset_broad=$false; create_computer_critical_ou=$false; create_user_privileged_ou=$false; unknown_object_guid=$false }
            [pscustomobject]@{ object_id='domain-root'; principal='synthetic-helpdesk'; right='WriteOwner'; unexpected=$true; dcsync_like=$false; modifies_privileged_group=$false; reset_privileged_password=$false; write_spn_privileged=$false; write_delegation_critical=$false; unexpected_owner=$true; unresolved_sid=$false; inherited_broad=$false; laps_read_broad=$false; laps_reset_broad=$false; create_computer_critical_ou=$false; create_user_privileged_ou=$false; unknown_object_guid=$false }
            [pscustomobject]@{ object_id='domain-root'; principal='synthetic-service'; right='ExtendedRight'; unexpected=$true; dcsync_like=$true; modifies_privileged_group=$false; reset_privileged_password=$false; write_spn_privileged=$false; write_delegation_critical=$false; unexpected_owner=$false; unresolved_sid=$false; inherited_broad=$false; laps_read_broad=$false; laps_reset_broad=$false; create_computer_critical_ou=$false; create_user_privileged_ou=$false; unknown_object_guid=$false }
            [pscustomobject]@{ object_id='adminsdholder'; principal='synthetic-helpdesk'; right='GenericAll'; unexpected=$true; dcsync_like=$false; modifies_privileged_group=$false; reset_privileged_password=$false; write_spn_privileged=$false; write_delegation_critical=$false; unexpected_owner=$false; unresolved_sid=$false; inherited_broad=$false; laps_read_broad=$false; laps_reset_broad=$false; create_computer_critical_ou=$false; create_user_privileged_ou=$false; unknown_object_guid=$false }
            [pscustomobject]@{ object_id='domain-admins'; principal='synthetic-helpdesk'; right='WriteProperty'; unexpected=$true; dcsync_like=$false; modifies_privileged_group=$true; reset_privileged_password=$true; write_spn_privileged=$true; write_delegation_critical=$false; unexpected_owner=$false; unresolved_sid=$false; inherited_broad=$false; laps_read_broad=$false; laps_reset_broad=$false; create_computer_critical_ou=$false; create_user_privileged_ou=$true; unknown_object_guid=$false }
            [pscustomobject]@{ object_id='domain-controllers-ou'; principal='Authenticated Users'; right='CreateChild'; unexpected=$true; dcsync_like=$false; modifies_privileged_group=$false; reset_privileged_password=$false; write_spn_privileged=$false; write_delegation_critical=$true; unexpected_owner=$false; unresolved_sid=$false; inherited_broad=$false; laps_read_broad=$false; laps_reset_broad=$false; create_computer_critical_ou=$true; create_user_privileged_ou=$false; unknown_object_guid=$false }
            [pscustomobject]@{ object_id='policies-container'; principal='synthetic-helpdesk'; right='GenericAll'; unexpected=$true; dcsync_like=$false; modifies_privileged_group=$false; reset_privileged_password=$false; write_spn_privileged=$false; write_delegation_critical=$false; unexpected_owner=$false; unresolved_sid=$false; inherited_broad=$false; laps_read_broad=$false; laps_reset_broad=$false; create_computer_critical_ou=$false; create_user_privileged_ou=$false; unknown_object_guid=$false }
            [pscustomobject]@{ object_id='laps'; principal='Authenticated Users'; right='ReadProperty'; unexpected=$true; dcsync_like=$false; modifies_privileged_group=$false; reset_privileged_password=$false; write_spn_privileged=$false; write_delegation_critical=$false; unexpected_owner=$false; unresolved_sid=$true; inherited_broad=$false; laps_read_broad=$true; laps_reset_broad=$true; create_computer_critical_ou=$false; create_user_privileged_ou=$false; unknown_object_guid=$true }
        )
        limitations = @('SYNTHETIC DEMONSTRATION DATA', 'This report contains synthetic Active Directory security-posture data created exclusively for demonstration, testing, and documentation purposes.', 'No real domain, forest, user, group, computer, trust, GPO, ACL, credential, or organization information is included.')
        excluded_sensitive_attributes = @(Get-ADSPBlockedAttributeList)
        snapshot_hash = ''
        blocked_attribute_detected = $false
    }

    $collectorIds = @('forest-domain','password-policies','users','groups','privileged-membership','computers','domain-controllers','service-accounts','gmsa-metadata','kerberos-metadata','delegation','trusts','authentication-policies','laps-metadata','laps-permissions','critical-object-acls','gpo-metadata','gpo-security-settings')
    $cols = @()
    foreach ($id in $collectorIds) {
        $cols += [pscustomobject]@{
            collector_id=$id; category='synthetic'; status='Collected'; started_at_utc=$now.ToString('o'); completed_at_utc=$now.ToString('o'); duration_ms=1; source_mode='Synthetic'; module_required='None'; module_available=$true; objects_examined=1; records_emitted=1; truncated=$false; warnings=@(); errors_redacted=@(); properties_requested=@('objectGuid','sAMAccountName'); sensitive_attributes_blocked=@(Get-ADSPBlockedAttributeList); limitations=@('synthetic'); collector_version='1.0.0'
        }
    }
    $snapshot.collectors = $cols
    $hash = Get-ADSPSnapshotHash -Snapshot ([pscustomobject]$snapshot)
    $snapshot.snapshot_hash = $hash
    $obj = [pscustomobject]$snapshot

    if ($OutputDirectory) {
        $out = Assert-ADSPSafePath -Path $OutputDirectory -IsOutput -AllowAbsolute
        if (-not (Test-Path -LiteralPath $out)) { New-Item -ItemType Directory -Path $out -Force | Out-Null }
        $snapPath = Join-Path $out 'snapshot.json'
        $json = ConvertTo-ADSPCanonicalJson -InputObject $obj
        [IO.File]::WriteAllText($snapPath, $json, [Text.UTF8Encoding]::new($false))
        $manifest = [pscustomobject]@{
            schema_version='1.0.0'
            snapshot_file='snapshot.json'
            snapshot_hash=$hash
            synthetic=$true
            marker='SYNTHETIC DEMONSTRATION DATA'
            generated_at_utc=$now.ToString('o')
        }
        $manPath = Join-Path $out 'snapshot.manifest.json'
        ($manifest | ConvertTo-Json -Depth 5) | Set-Content -LiteralPath $manPath -Encoding UTF8
    }
    return $obj
}
