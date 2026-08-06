@{
    Severity     = @('Error', 'Warning')
    # Justified residual exclusions (see docs/security-audit-v1.0.0.md):
    # - PSUseSingularNouns: collector/evaluator names mirror AD plural object classes and stable collector IDs.
    # - PSUseBOMForUnicodeEncodedFile: UTF-8 without BOM is intentional for cross-platform PowerShell/Git.
    # - PSUseShouldProcessForStateChangingFunctions: New-ADSP* constructs report objects/files under Assert-ADSPSafePath; they never mutate Active Directory.
    # - PSAvoidUsingWriteHost: CLI/run-ci operator summaries intentionally write to the host; module data paths use objects/pipeline.
    ExcludeRules = @(
        'PSUseSingularNouns'
        'PSUseBOMForUnicodeEncodedFile'
        'PSUseShouldProcessForStateChangingFunctions'
        'PSAvoidUsingWriteHost'
    )
    Rules        = @{
        PSAvoidUsingCmdletAliases             = @{ Enable = $true }
        PSUseApprovedVerbs                    = @{ Enable = $true }
        PSAvoidGlobalVars                     = @{ Enable = $true }
        PSUseDeclaredVarsMoreThanAssignments  = @{ Enable = $true }
        PSReviewUnusedParameter               = @{ Enable = $true }
        PSAvoidAssignmentToAutomaticVariable  = @{ Enable = $true }
        PSAvoidUsingEmptyCatchBlock           = @{ Enable = $true }
    }
}
