# Indentured Servant — AI Cybersecurity Toolkit

[![CI](https://github.com/<owner>/<repo>/actions/workflows/ci.yml/badge.svg)](https://github.com/<owner>/<repo>/actions/workflows/ci.yml)

A local-first AI assistant for small-scale cybersecurity tasks: vulnerability scanning, network analysis, email analysis, and secure reporting.

## Quickstart
- Configure `config/ai_cyber_helper.json` as needed.
- Run the GUI: `python -m src.main` (if available) or use CLI via `python -m src.ai_cyber_helper --scan 127.0.0.1`.

## Documentation
- Usage guide: `docs/usage.md`
- Config reference: `docs/config_reference.md`
- Development & tests: `docs/development.md`

## Features
- Local TCP connect scanner with banner grab and CVE DB lookup
- PCAP parsing with port-scan, DNS anomalies, and beaconing heuristics
- GUI tab for scans & PCAP analysis
- CI tests covering core functions

## Notes
- Replace the badge URL with your repository's owner/name to show real status.
- Keep online lookups disabled for sensitive networks by default; update `config/ai_cyber_helper.json` to enable opt-in services.