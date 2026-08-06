function ConvertTo-ADSPPrivacyValue {
    [CmdletBinding()]
    param(
        [AllowNull()]$Value,
        [Parameter(Mandatory)][ValidateSet('Masked','Hashed','Full')]$PrivacyMode,
        [ValidateSet('domain','forest','host','user','group','dn','sid','generic')]$Kind = 'generic',
        [hashtable]$AliasMap,
        [string]$Salt
    )
    if ($null -eq $Value -or $Value -eq '') { return $Value }
    $text = [string]$Value
    if ($PrivacyMode -eq 'Full') { return $text }

    if ($PrivacyMode -eq 'Hashed') {
        if ([string]::IsNullOrEmpty($Salt) -and $env:ADSP_PRIVACY_SALT) { $Salt = $env:ADSP_PRIVACY_SALT }
        if ([string]::IsNullOrEmpty($Salt)) { throw 'Hashed privacy mode requires ADSP_PRIVACY_SALT or -Salt (except deterministic synthetic helpers).' }
        $bytes = [Text.Encoding]::UTF8.GetBytes($Salt + '|' + $Kind + '|' + $text)
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try {
            $hash = $sha.ComputeHash($bytes)
            return ($Kind.ToUpperInvariant() + '-' + (([BitConverter]::ToString($hash) -replace '-', '').Substring(0, 16).ToLowerInvariant()))
        } finally { $sha.Dispose() }
    }

    # Masked
    if ($Kind -eq 'sid' -and $text -match '^S-1-5-32-') { return $text }
    if ($null -ne $AliasMap -and $AliasMap.ContainsKey($text)) { return $AliasMap[$text] }
    $prefix = switch ($Kind) {
        'domain' { 'DOMAIN' }
        'forest' { 'FOREST' }
        'host' { 'HOST' }
        'user' { 'USER' }
        'group' { 'GROUP' }
        'dn' { 'DN' }
        'sid' { 'SID' }
        default { 'ID' }
    }
    $n = if ($null -ne $AliasMap) { $AliasMap.Count + 1 } else { 1 }
    $alias = "{0}-{1:D3}" -f $prefix, $n
    if ($null -ne $AliasMap) { $AliasMap[$text] = $alias }
    return $alias
}


