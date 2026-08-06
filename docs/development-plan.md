# Development Plan — active-directory-security-posture-auditor 1.0.0

## Objective

Build a PowerShell-first Active Directory Domain Services security-posture auditor that supports synthetic, imported, and explicitly acknowledged read-only live snapshot modes; evaluates privileged access, account hygiene, Kerberos, delegation, service accounts, domain controllers, Windows LAPS metadata, trusts, selected GPO settings, and critical-object ACLs; and produces JSON, CSV, and standalone HTML reports with policy profiles, scoring, suppressions, and privacy modes.

## Constraints

- Never modify Active Directory.
- Never retrieve passwords, hashes, LAPS passwords, or gMSA managed-password blobs.
- Never query a real domain during development or CI.
- Use only synthetic demonstration data in tracked examples.
- Live collection requires dual acknowledgement and is never the default.

## Phase Summary

| Phase | Focus | Status |
|------:|-------|--------|
| 1 | Inspect directory and write this plan | Done |
| 2 | Repository structure and metadata | In progress |
| 3–6 | Module, models, canonical JSON, snapshot validation | Planned |
| 7–10 | Blocked attributes, synthetic data, collectors, live guards | Planned |
| 11–14 | Membership, ACL, GPO parsing, configuration | Planned |
| 15–21 | Rule registry and category evaluators (≥110 rules) | Planned |
| 22–25 | Scoring, suppressions, privacy, reports, comparison | Planned |
| 26–28 | CLI, synthetic examples, sample reports/screenshot | Planned |
| 29–32 | ≥220 Pester tests, PSScriptAnalyzer, CI, docs | Planned |
| 33–37 | Local validation, security audit, git init/commit | Planned |

## Architecture Modes

1. **Synthetic** — repository fixtures only; never queries host or directory.
2. **Imported** — operator-supplied JSON snapshot; never reconnects.
3. **Live** — read-only AD queries only after dual acknowledgement.

## Delivery Order

Implement private helpers first, then public API, collectors (unguarded execution path only behind acknowledgements), rule engine, reports, CLI, fixtures, tests, CI, documentation, then synthetic-only validation and local git commit with noreply identity.

## Out of Scope (v1.0)

Microsoft Entra ID, Graph, AD CS, AD FS live analysis, BloodHound, password cracking, runtime monitoring, automatic remediation, SaaS reporting.
