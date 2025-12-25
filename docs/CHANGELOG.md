# Changelog

## v0.1.0 - 2025-12-24

Initial release

### Added
- AI Cybersecurity Helper module (`src/ai_cyber_helper.py`) with:
  - Local vulnerability scanning (TCP connect, banner grab, CVE lookup via local DB)
  - Network analysis heuristics (PCAP parsing, port-scan detection, DNS anomalies, beaconing/C2 heuristics)
- GUI integration: `Cyber Helper` tab with scan controls and PCAP analysis
- Safety & privacy features: safe-mode (skip public addresses), persisted consent, anonymize reports
- CLI & scripts: cross-platform auto-venv launcher and Windows convenience batch script
- Tests: unit tests covering core functionality and safety features
- CI: GitHub Actions workflow for tests

### Changed
- Added docs: usage, config reference, development notes, changelog

### Packaging
- Added PyInstaller packaging scripts and CI packaging job for release artifacts

### Notes
- All analysis is local by default. Online lookups are opt-in via config.
