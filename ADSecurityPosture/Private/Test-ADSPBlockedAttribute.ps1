function Test-ADSPBlockedAttribute {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [string]$RepoRoot = $script:ADSPRepoRoot
    )
    $path = Join-Path $RepoRoot 'config/sensitive-attributes.json'
    $cfg = Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json
    $blocked = @($cfg.blocked_attributes | ForEach-Object { $_.ToLowerInvariant() })
    return $blocked -contains $Name.ToLowerInvariant()
}

function Assert-ADSPNoBlockedAttributes {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Object, [string]$PathHint = 'object')
    $json = $Object | ConvertTo-Json -Depth 100 -Compress
    $cfgPath = Join-Path $script:ADSPRepoRoot 'config/sensitive-attributes.json'
    $cfg = Get-Content -LiteralPath $cfgPath -Raw -Encoding UTF8 | ConvertFrom-Json
    foreach ($attr in $cfg.blocked_attributes) {
        # Detect property names in JSON (quoted)
        $pattern = '"' + [regex]::Escape($attr) + '"\s*:'
        if ($json -imatch $pattern) {
            throw "Blocked sensitive attribute '$attr' detected in $PathHint. Refuse to continue."
        }
    }
}

function Get-ADSPBlockedAttributeList {
    $cfgPath = Join-Path $script:ADSPRepoRoot 'config/sensitive-attributes.json'
    $cfg = Get-Content -LiteralPath $cfgPath -Raw -Encoding UTF8 | ConvertFrom-Json
    return @($cfg.blocked_attributes)
}
