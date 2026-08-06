# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 1.0.x   | Yes       |

## Reporting a vulnerability

Please report security issues privately via GitHub Security Advisories for this repository.

Do not open public issues that include:

- Real directory snapshots
- Credentials, password hashes, LAPS values, or gMSA managed-password data
- Personal or organizational identity metadata

## In-scope concerns

- Sensitive attribute leakage into snapshots, logs, or reports
- Unsafe live queries or missing acknowledgement gates
- Introduction of modifying AD/GPO cmdlets
- Path traversal or symlink escape in output handling
- Snapshot tampering / hash bypass without clear Untrusted marking
- HTML injection in reports
- CSV formula injection
- Suppression bypass for Critical findings without policy controls

## Out of scope

- Claims that a posture score certifies security or compliance
- Equivalence to Microsoft Defender for Identity
- Real-time detection or authentication-traffic monitoring

## Responsible disclosure

Allow reasonable time for remediation before public disclosure. Do not exploit production directories.
