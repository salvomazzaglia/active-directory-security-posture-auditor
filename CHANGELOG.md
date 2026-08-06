# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-01-15

### Added

- PowerShell module `ADSecurityPosture` for Active Directory security-posture assessment
- Synthetic, imported, and explicitly acknowledged read-only live snapshot modes
- Offline snapshot validation and SHA-256 integrity hashing
- Privileged-access expansion with cycle-safe nested membership analysis
- Policy profiles: baseline, strict, legacy-compatible
- Rule registry with 170+ policy-driven findings across domain, privilege, account, Kerberos, LAPS, trust, GPO, and ACL categories
- JSON, CSV, and standalone HTML reports with Masked/Hashed/Full privacy modes
- Snapshot comparison and security-drift reporting
- Pester tests, PSScriptAnalyzer settings, and GitHub-hosted CI

### Security

- Blocked-attribute registry preventing password, LAPS, and gMSA secret serialization
- Live collection dual-acknowledgement gates
- No modifying AD/GPO cmdlets; no password retrieval; no offensive tooling
