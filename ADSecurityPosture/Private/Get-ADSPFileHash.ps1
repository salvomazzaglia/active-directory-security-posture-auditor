function Get-ADSPFileHash {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [ValidateSet('SHA256')]$Algorithm = 'SHA256'
    )
    if ($Algorithm -ne 'SHA256') { throw "Unsupported hash algorithm: $Algorithm" }
    $bytes = [IO.File]::ReadAllBytes($Path)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hash = $sha.ComputeHash($bytes)
        return ([BitConverter]::ToString($hash) -replace '-', '').ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}

function Copy-ADSPObjectWithoutHash {
    param($Snapshot)
    # Structural clone without ConvertTo-Json round-trip (not portable across PowerShell hosts).
    if ($null -eq $Snapshot) { return $null }
    if ($Snapshot -is [string] -or $Snapshot -is [bool] -or $Snapshot -is [byte] -or $Snapshot -is [sbyte] -or
        $Snapshot -is [int16] -or $Snapshot -is [uint16] -or $Snapshot -is [int] -or $Snapshot -is [uint32] -or
        $Snapshot -is [long] -or $Snapshot -is [uint64] -or $Snapshot -is [decimal] -or $Snapshot -is [double] -or
        $Snapshot -is [float] -or $Snapshot -is [char] -or $Snapshot -is [guid] -or $Snapshot -is [enum]) {
        return $Snapshot
    }
    if ($Snapshot -is [datetime]) { return $Snapshot }
    if ($Snapshot -is [System.Collections.IDictionary]) {
        $ordered = [ordered]@{}
        foreach ($k in $Snapshot.Keys) {
            if ([string]$k -eq 'snapshot_hash') { continue }
            $ordered[[string]$k] = Copy-ADSPObjectWithoutHash -Snapshot $Snapshot[$k]
        }
        return $ordered
    }
    if ($Snapshot -is [System.Collections.IEnumerable] -and -not ($Snapshot -is [string])) {
        $list = New-Object System.Collections.Generic.List[object]
        foreach ($item in $Snapshot) { $list.Add((Copy-ADSPObjectWithoutHash -Snapshot $item)) | Out-Null }
        return $list.ToArray()
    }
    $ordered = [ordered]@{}
    foreach ($p in @($Snapshot.PSObject.Properties | Where-Object { $_.MemberType -match 'NoteProperty|Property' })) {
        if ($p.Name -eq 'snapshot_hash') { continue }
        if ($p.Name -in @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider')) { continue }
        $ordered[$p.Name] = Copy-ADSPObjectWithoutHash -Snapshot $p.Value
    }
    return $ordered
}

function Get-ADSPSnapshotHash {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Snapshot)
    $clone = Copy-ADSPObjectWithoutHash -Snapshot $Snapshot
    $canonical = ConvertTo-ADSPCanonicalJson -InputObject $clone
    $bytes = [Text.Encoding]::UTF8.GetBytes($canonical)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hash = $sha.ComputeHash($bytes)
        return ([BitConverter]::ToString($hash) -replace '-', '').ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}
