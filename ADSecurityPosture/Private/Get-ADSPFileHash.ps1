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

function Get-ADSPSnapshotHash {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Snapshot)
    $clone = $Snapshot | ConvertTo-Json -Depth 100 | ConvertFrom-Json
    if ($clone.PSObject.Properties.Name -contains 'snapshot_hash') {
        $clone.PSObject.Properties.Remove('snapshot_hash')
    }
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
