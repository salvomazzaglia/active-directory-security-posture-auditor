function New-ADSPJsonReport {
    param([Parameter(Mandatory)]$Report, [Parameter(Mandatory)][string]$Path)
    $json = ConvertTo-ADSPCanonicalJson -InputObject $Report
    Assert-ADSPNoBlockedAttributes -Object $Report -PathHint 'json-report'
    [IO.File]::WriteAllText($Path, $json, [Text.UTF8Encoding]::new($false))
}
