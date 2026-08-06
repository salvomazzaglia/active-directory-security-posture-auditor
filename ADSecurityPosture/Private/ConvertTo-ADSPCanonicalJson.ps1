function ConvertTo-ADSPCanonicalJson {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$InputObject)

    $sb = New-Object System.Text.StringBuilder

    function Append-EscapedString {
        param([System.Text.StringBuilder]$Builder, [string]$Value)
        [void]$Builder.Append('"')
        foreach ($ch in $Value.ToCharArray()) {
            switch ($ch) {
                '"' { [void]$Builder.Append('\"') }
                '\' { [void]$Builder.Append('\\') }
                "`b" { [void]$Builder.Append('\b') }
                "`f" { [void]$Builder.Append('\f') }
                "`n" { [void]$Builder.Append('\n') }
                "`r" { [void]$Builder.Append('\r') }
                "`t" { [void]$Builder.Append('\t') }
                default {
                    $code = [int][char]$ch
                    if ($code -lt 0x20) {
                        [void]$Builder.AppendFormat('\u{0:x4}', $code)
                    } else {
                        [void]$Builder.Append($ch)
                    }
                }
            }
        }
        [void]$Builder.Append('"')
    }

    function Write-CanonicalValue {
        param($Builder, $Obj)
        if ($null -eq $Obj) {
            [void]$Builder.Append('null')
            return
        }
        if ($Obj -is [bool]) {
            [void]$Builder.Append($(if ($Obj) { 'true' } else { 'false' }))
            return
        }
        if ($Obj -is [byte] -or $Obj -is [sbyte] -or $Obj -is [int16] -or $Obj -is [uint16] -or
            $Obj -is [int] -or $Obj -is [uint32] -or $Obj -is [long] -or $Obj -is [uint64] -or
            $Obj -is [decimal] -or $Obj -is [double] -or $Obj -is [float] -or $Obj -is [bigint]) {
            [void]$Builder.Append(($Obj.ToString([System.Globalization.CultureInfo]::InvariantCulture)))
            return
        }
        if ($Obj -is [datetime]) {
            Append-EscapedString -Builder $Builder -Value ($Obj.ToUniversalTime().ToString('o'))
            return
        }
        if ($Obj -is [string] -or $Obj -is [char] -or $Obj -is [guid] -or $Obj -is [enum]) {
            Append-EscapedString -Builder $Builder -Value ([string]$Obj)
            return
        }
        if ($Obj -is [System.Collections.IDictionary]) {
            $keys = @($Obj.Keys | ForEach-Object { $_.ToString() } | Sort-Object)
            [void]$Builder.Append('{')
            $first = $true
            foreach ($k in $keys) {
                if (-not $first) { [void]$Builder.Append(',') }
                $first = $false
                Append-EscapedString -Builder $Builder -Value $k
                [void]$Builder.Append(':')
                Write-CanonicalValue -Builder $Builder -Obj $Obj[$k]
            }
            [void]$Builder.Append('}')
            return
        }
        if ($Obj -is [System.Collections.IEnumerable] -and -not ($Obj -is [string])) {
            [void]$Builder.Append('[')
            $first = $true
            foreach ($item in $Obj) {
                if (-not $first) { [void]$Builder.Append(',') }
                $first = $false
                Write-CanonicalValue -Builder $Builder -Obj $item
            }
            [void]$Builder.Append(']')
            return
        }

        $props = @($Obj.PSObject.Properties | Where-Object {
            $_.MemberType -match 'NoteProperty|Property' -and
            $_.Name -notin @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider')
        } | Sort-Object Name)
        [void]$Builder.Append('{')
        $first = $true
        foreach ($p in $props) {
            if (-not $first) { [void]$Builder.Append(',') }
            $first = $false
            Append-EscapedString -Builder $Builder -Value $p.Name
            [void]$Builder.Append(':')
            Write-CanonicalValue -Builder $Builder -Obj $p.Value
        }
        [void]$Builder.Append('}')
    }

    Write-CanonicalValue -Builder $sb -Obj $InputObject
    return $sb.ToString()
}
