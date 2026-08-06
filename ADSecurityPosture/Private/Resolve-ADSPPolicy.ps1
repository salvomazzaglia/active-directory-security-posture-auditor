# Resolve-ADSPPolicy lives with scoring helpers for shared load.
# Re-export wrappers kept here for file-structure compliance.

function Resolve-ADSPPolicy {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$PolicyPath)
    $full = Assert-ADSPSafePath -Path $PolicyPath -AllowAbsolute -MustExist
    $policy = Get-Content -LiteralPath $full -Raw -Encoding UTF8 | ConvertFrom-Json
    if (-not $policy.scoring) { throw 'Policy missing scoring section.' }
    if (-not $policy.thresholds) { throw 'Policy missing thresholds section.' }
    return $policy
}
