function ConvertTo-ADSPCanonicalJson {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$InputObject)

    function ConvertTo-ADSPSortedObject {
        param($Obj)
        if ($null -eq $Obj) { return $null }
        if ($Obj -is [string] -or $Obj -is [bool] -or $Obj -is [int] -or $Obj -is [long] -or $Obj -is [double] -or $Obj -is [decimal]) {
            return $Obj
        }
        if ($Obj -is [datetime]) { return $Obj.ToUniversalTime().ToString('o') }
        if ($Obj -is [System.Collections.IDictionary]) {
            $ordered = [ordered]@{}
            foreach ($k in ($Obj.Keys | Sort-Object { $_.ToString() })) {
                $ordered[$k.ToString()] = ConvertTo-ADSPSortedObject -Obj $Obj[$k]
            }
            return $ordered
        }
        if ($Obj -is [System.Collections.IEnumerable] -and -not ($Obj -is [string])) {
            $list = @()
            foreach ($item in $Obj) { $list += ,(ConvertTo-ADSPSortedObject -Obj $item) }
            return $list
        }
        $props = $Obj.PSObject.Properties | Where-Object { $_.MemberType -match 'NoteProperty|Property' } | Sort-Object Name
        $ordered = [ordered]@{}
        foreach ($p in $props) {
            $ordered[$p.Name] = ConvertTo-ADSPSortedObject -Obj $p.Value
        }
        return $ordered
    }

    $sorted = ConvertTo-ADSPSortedObject -Obj $InputObject
    return ($sorted | ConvertTo-Json -Depth 100)
}
