# Security audit v1.0.0

## Scope

Checks performed for the public 1.0.0 release: synthetic-only examples, blocked-attribute enforcement, no modifying Active Directory/GPO cmdlets, no secret/LAPS/gMSA retrieval, CI safety (no live `collect`, no self-hosted runners, no `pull_request_target`), path guards, HTML offline/standalone, and CSV formula-injection controls.

## PSScriptAnalyzer triage (release gate)

Initial scan before publication triage reported **27 Warning** findings when scoped to the module surface used for the earlier local gate, and a broader recurse over module/scripts/collectors/tests surfaced additional style findings. After remediation:

| Metric | Result |
| --- | --- |
| Error | **0** |
| Warning | **0** |
| Residual warnings | **none** |

### Corrected defect classes

- Approved-verb nested helper rename (`Sort-ADSPObject` → `ConvertTo-ADSPSortedObject`)
- Empty `catch` replaced with operator warning
- Unused assignments (`$pwd` automatic-variable conflict, unused locals, unused `$Algorithm`)
- Collector scripts regenerated so each collector file contains only its own allowlisted logic
- Evaluator `Policy` null-guards; CSV `PrivacyMode` validation; `run-ci.ps1` unused-variable usage
- Pester script-scope `$RepoRoot` assignments restructured so analyzer sees real uses

### Justified analyzer exclusions (`PSScriptAnalyzerSettings.psd1`)

These rules remain excluded with documented rationale (not silent global silencing of Errors):

| Rule | Justification |
| --- | --- |
| `PSUseSingularNouns` | Collector/evaluator names mirror AD plural object classes and stable collector IDs. |
| `PSUseBOMForUnicodeEncodedFile` | UTF-8 without BOM is intentional for cross-platform PowerShell and Git. |
| `PSUseShouldProcessForStateChangingFunctions` | `New-ADSP*` constructs report objects/files under `Assert-ADSPSafePath`; they never mutate Active Directory. |
| `PSAvoidUsingWriteHost` | CLI/`run-ci` operator summaries intentionally write to the host; module data paths use objects/pipeline. |

## Comparison fixture note

`examples/comparison/` demonstrates meaningful synthetic drift: resolved privileged memberships/ACLs/delegation issues, newly introduced operator membership and ACL/delegation drift, and a **non-zero** `score_delta` under baseline policy. Compensating Masked privacy aliases are not used as the sole drift signal; Full-privacy target keys and membership lists confirm real changes.

## Limitations

Offline snapshots become stale; findings require operational review; score and grade are prioritization aids, **not certification**. This project is not Microsoft Defender for Identity and does not perform behavioral detection or secret retrieval.
