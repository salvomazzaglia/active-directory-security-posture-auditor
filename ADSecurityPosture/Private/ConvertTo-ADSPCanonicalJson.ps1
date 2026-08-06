function ConvertTo-ADSPCanonicalJson {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$InputObject)

    function Sort-ADSPObject($obj) {
        if ($null -eq $obj) { return $null }
        if ($obj -is [string] -or $obj -is [bool] -or $obj -is [int] -or $obj -is [long] -or $obj -is [double] -or $obj -is [decimal]) {
            return $obj
        }
        if ($obj -is [datetime]) { return $obj.ToUniversalTime().ToString('o') }
        if ($obj -is [System.Collections.IDictionary]) {
            $ordered = [ordered]@{}
            foreach ($k in ($obj.Keys | Sort-Object { $_.ToString() })) {
                $ordered[$k.ToString()] = Sort-ADSPObject $obj[$k]
            }
            return $ordered
        }
        if ($obj -is [System.Collections.IEnumerable] -and -not ($obj -is [string])) {
            $list = @()
            foreach ($item in $obj) { $list += ,(Sort-ADSPObject $item) }
            return $list
        }
        # PSCustomObject
        $props = $obj.PSObject.Properties | Where-Object { $_.MemberType -match 'NoteProperty|Property' } | Sort-Object Name
        $ordered = [ordered]@{}
        foreach ($p in $props) {
            $ordered[$p.Name] = Sort-ADSPObject $p.Value
        }
        return $ordered
    }

    $sorted = Sort-ADSPObject $InputObject
    return ($sorted | ConvertTo-Json -Depth 100)
}
