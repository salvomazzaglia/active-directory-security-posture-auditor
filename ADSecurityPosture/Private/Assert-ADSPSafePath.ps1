function Assert-ADSPSafePath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$AllowAbsolute,
        [switch]$MustExist,
        [switch]$IsOutput,
        [switch]$AllowOverwrite,
        [string]$RepoRoot = $script:ADSPRepoRoot
    )
    if ([string]::IsNullOrWhiteSpace($Path)) { throw 'Path is empty.' }
    if ($Path.Contains([char]0)) { throw 'Path contains NUL.' }
    if ($Path -match '(^|\\|/)\.\.(\\|_|/|$)') { throw "Path traversal rejected: $Path" }
    $invalid = [IO.Path]::GetInvalidFileNameChars() + [IO.Path]::GetInvalidPathChars() | Select-Object -Unique
    $leaf = Split-Path -Leaf $Path
    $reserved = @('CON','PRN','AUX','NUL','COM1','COM2','COM3','COM4','LPT1','LPT2','LPT3')
    if ($reserved -contains ($leaf.Split('.')[0].ToUpperInvariant())) { throw "Reserved filename rejected: $leaf" }
    if ($Path.Length -gt 240) { throw 'Path exceeds safe length.' }

    $full = if ([IO.Path]::IsPathRooted($Path)) {
        if (-not $AllowAbsolute -and -not $IsOutput) { throw "Absolute path not allowed: $Path" }
        [IO.Path]::GetFullPath($Path)
    } else {
        [IO.Path]::GetFullPath((Join-Path $RepoRoot $Path))
    }

    $repoFull = [IO.Path]::GetFullPath($RepoRoot)
    $sensitive = @('C:\Windows', 'C:\Windows\System32', '/etc', '/usr', '/bin', '/sbin')
    foreach ($s in $sensitive) {
        if ($full.StartsWith($s, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Sensitive system path refused: $full"
        }
    }
    if ($full -match '^[A-Za-z]:\\?$' -or $full -eq '/' -or $full -eq '\') {
        throw "Root directory refused: $full"
    }
    $moduleSrc = [IO.Path]::GetFullPath((Join-Path $RepoRoot 'ADSecurityPosture'))
    if ($IsOutput -and $full.StartsWith($moduleSrc, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Output inside module source refused.'
    }
    if ($MustExist -and -not (Test-Path -LiteralPath $full)) { throw "Path does not exist: $full" }
    if ($IsOutput -and (Test-Path -LiteralPath $full) -and -not $AllowOverwrite) {
        if ((Get-Item -LiteralPath $full).PSIsContainer) {
            $children = @(Get-ChildItem -LiteralPath $full -Force -ErrorAction SilentlyContinue)
            if ($children.Count -gt 0) { throw "Output directory not empty and overwrite refused: $full" }
        } else {
            throw "Output overwrite refused: $full"
        }
    }
    try {
        $item = Get-Item -LiteralPath $full -Force -ErrorAction SilentlyContinue
        if ($item -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw "Symlink/reparse point rejected: $full"
        }
    } catch {
        if ($_.Exception.Message -match 'Symlink') { throw }
    }
    return $full
}
