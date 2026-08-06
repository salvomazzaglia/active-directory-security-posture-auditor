# Contributing

Thank you for contributing to **active-directory-security-posture-auditor**.

## Development setup

1. Clone the repository
2. Use PowerShell 7.4+ (Windows or Ubuntu offline) or Windows PowerShell 5.1 for compatibility checks
3. Install Pester 5.x and PSScriptAnalyzer from PSGallery
4. Run `pwsh ./scripts/run-ci.ps1`

## Rules

- Use approved PowerShell verbs
- Allocate new rule IDs in the correct `ADSP-` family without reuse
- Collectors must be repository-maintained and allowlisted
- Review blocked-attribute changes carefully
- Add meaningful Pester coverage for new rules and guards
- Keep PSScriptAnalyzer clean
- Use synthetic fixtures only (`corp.example.invalid`)
- Document behavior and limitations

## Prohibited

- Real domain data, credentials, or personal paths
- Live directory queries in CI
- Modifying AD/GPO cmdlets
- Password, LAPS password, or gMSA managed-password retrieval
- Offensive tooling (SharpHound, Mimikatz, Rubeus, secretsdump, roasting, spraying)
- `Invoke-Expression` / dynamic scriptblocks from configuration
- Self-hosted runners or `pull_request_target`

## Pull request checklist

- [ ] Synthetic-only examples
- [ ] Tests added/updated
- [ ] Docs updated
- [ ] No blocked attributes in outputs
- [ ] `scripts/run-ci.ps1` passes locally where applicable
