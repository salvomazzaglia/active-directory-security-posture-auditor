function Write-ADSPConsole {
    # CLI-facing colored console output is intentional for operator acknowledgements and warnings.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Confined console helper for CLI acknowledgements and operator warnings; not used for pipeline data.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('Info','Warn','Error','Success')]$Level = 'Info'
    )
    $color = switch ($Level) {
        'Warn' { 'Yellow' }
        'Error' { 'Red' }
        'Success' { 'Green' }
        default { 'Cyan' }
    }
    Write-Host $Message -ForegroundColor $color
}
