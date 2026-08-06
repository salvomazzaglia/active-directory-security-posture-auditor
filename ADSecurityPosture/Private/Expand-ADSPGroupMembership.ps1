function Expand-ADSPGroupMembership {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$GroupKey,
        [Parameter(Mandatory)]$MembershipIndex,
        [Parameter(Mandatory)]$PrincipalIndex,
        [int]$MaxDepth = 8,
        [int]$MaxObjects = 5000
    )
    $results = New-Object System.Collections.Generic.List[object]
    $visitedGlobal = @{}
    $stack = New-Object System.Collections.Generic.Stack[object]
    $stack.Push(@{ Key = $GroupKey; Path = @($GroupKey); Depth = 0; Visited = @{} })

    while ($stack.Count -gt 0) {
        if ($results.Count -ge $MaxObjects) {
            return @{ Members = $results; Truncated = $true; CycleDetected = $false }
        }
        $frame = $stack.Pop()
        if ($frame.Depth -gt $MaxDepth) { continue }
        $key = $frame.Key
        if (-not $MembershipIndex.ContainsKey($key)) { continue }
        foreach ($memberKey in @($MembershipIndex[$key])) {
            $path = @($frame.Path + $memberKey)
            $cycle = $frame.Visited.ContainsKey($memberKey)
            $principal = if ($PrincipalIndex.ContainsKey($memberKey)) { $PrincipalIndex[$memberKey] } else { $null }
            $entry = [pscustomobject]@{
                member_key = $memberKey
                depth = $frame.Depth + 1
                path = $path
                cycle = [bool]$cycle
                principal = $principal
                membership_type = if ($frame.Depth -eq 0) { 'Direct' } else { 'Transitive' }
            }
            $results.Add($entry) | Out-Null
            if ($cycle) { continue }
            $nextVisited = @{}
            foreach ($vk in $frame.Visited.Keys) { $nextVisited[$vk] = $true }
            $nextVisited[$memberKey] = $true
            if ($MembershipIndex.ContainsKey($memberKey)) {
                $stack.Push(@{ Key = $memberKey; Path = $path; Depth = $frame.Depth + 1; Visited = $nextVisited })
            }
        }
    }
    $cycleDetected = @($results | Where-Object { $_.cycle }).Count -gt 0
    return @{ Members = $results; Truncated = $false; CycleDetected = $cycleDetected }
}
