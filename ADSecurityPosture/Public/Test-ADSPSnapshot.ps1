function Test-ADSPSnapshot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SnapshotPath,
        [switch]$SkipHashValidation,
        [switch]$AllowHashMismatch
    )
    $errors = New-Object System.Collections.Generic.List[string]
    try {
        $snap = Import-ADSPSnapshotInternal -Path $SnapshotPath
        foreach ($req in @('schema_version','tool_name','tool_version','snapshot_id','source_mode','users','groups')) {
            if (-not ($snap.PSObject.Properties.Name -contains $req)) { $errors.Add("Missing section: $req") | Out-Null }
        }
        if ($snap.schema_version -ne '1.0.0') { $errors.Add("Unsupported schema $($snap.schema_version)") | Out-Null }
        Assert-ADSPNoBlockedAttributes -Object $snap -PathHint $SnapshotPath
        if (-not $SkipHashValidation) {
            $expected = Get-ADSPSnapshotHash -Snapshot $snap
            if ([string]$snap.snapshot_hash -ne $expected) {
                if ($AllowHashMismatch) { $errors.Add('Hash mismatch (allowed for diagnostics; mark Untrusted)') | Out-Null }
                else { $errors.Add("Snapshot hash mismatch. Expected $expected") | Out-Null }
            }
        }
        $guids = @{}
        foreach ($u in @($snap.users)) {
            if ($guids.ContainsKey([string]$u.object_guid)) { $errors.Add("Duplicate object_guid $($u.object_guid)") | Out-Null }
            $guids[[string]$u.object_guid] = $true
        }
    } catch { $errors.Add($_.Exception.Message) | Out-Null }
    return [pscustomobject]@{ valid = ($errors.Count -eq 0); errors = @($errors) }
}
