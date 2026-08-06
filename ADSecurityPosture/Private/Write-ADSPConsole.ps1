function Write-ADSPConsole {
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
