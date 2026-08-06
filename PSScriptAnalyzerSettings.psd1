@{
    Severity = @('Error', 'Warning')
    ExcludeRules = @()
    Rules = @{
        PSAvoidUsingCmdletAliases = @{ Enable = $true }
        PSUseApprovedVerbs = @{ Enable = $true }
        PSAvoidUsingWriteHost = @{ Enable = $true }
        PSAvoidGlobalVars = @{ Enable = $true }
        PSUseDeclaredVarsMoreThanAssignments = @{ Enable = $true }
    }
}
