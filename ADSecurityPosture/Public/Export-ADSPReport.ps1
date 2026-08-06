function Export-ADSPReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$AuditResult,
        [Parameter(Mandatory)][string]$OutputDirectory,
        [ValidateSet('Json','Csv','Html','All')]$Format = 'All',
        [ValidateSet('Masked','Hashed','Full')]$PrivacyMode = 'Masked'
    )
    $out = Assert-ADSPSafePath -Path $OutputDirectory -IsOutput -AllowAbsolute
    if (-not (Test-Path -LiteralPath $out)) { New-Item -ItemType Directory -Path $out -Force | Out-Null }
    Assert-ADSPNoBlockedAttributes -Object $AuditResult -PathHint 'audit-result'
    if ($Format -in @('Json','All')) { New-ADSPJsonReport -Report $AuditResult -Path (Join-Path $out 'report.json') }
    if ($Format -in @('Csv','All')) { New-ADSPCsvReport -Report $AuditResult -OutputDirectory $out -PrivacyMode $PrivacyMode }
    if ($Format -in @('Html','All')) { New-ADSPHtmlReport -Report $AuditResult -Path (Join-Path $out 'report.html') }
}
