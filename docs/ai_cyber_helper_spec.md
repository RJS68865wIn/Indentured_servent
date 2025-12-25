AI Cybersecurity Helper — One‑Page Spec

Purpose
- Provide local, non-intrusive automated assistance for: (B) local vulnerability scanning and (C) network traffic analysis. The assistant will produce concise findings and mitigation suggestions, suitable for use via CLI or GUI.

Priority
- Primary: Local Vulnerability Scanning (B)
- Secondary: Network Traffic Analysis (C)

Core features
- Vulnerability scanner
  - Local host/target scanning: ports, services, version detection
  - CVE lookup via offline DB or optional online lookup (configurable)
  - Safety: no destructive exploits; timeouts and rate limits
  - Report: found issues, severity (low/med/high/critical), suggested mitigations

- Network analysis
  - PCAP ingestion and live interface capture (optional)
  - Flow extraction, suspicious IP/port detection, anomaly heuristics
  - Integration with local IDS signature sets (optional)
  - Report: suspicious flows, possible indicators of compromise (IoC)

Interfaces & Integration
- Core module: `src/ai_cyber_helper.py` with functions: `scan_targets`, `analyze_network_traffic`, `suggest_mitigation`, `report_results`.
- Config: `config/ai_cyber_helper.json` for safe defaults and toggles (enable/disable modules, timeouts, data paths).
- GUI: new tab in `src/gui` with start/stop controls, progress view, and results panel.
- Tests: unit tests for parsing, report generation, and simulation of scan output.

Security & Privacy
- Do not send sensitive data to remote services by default; opt-in required for any network/API lookups.
- Strict logging (anonymize PII where feasible) and rate limiting for scans.

Acceptance criteria
- Able to run a local vulnerability scan and produce a JSON report with severity tagging and suggested mitigation steps.
- Able to analyze a sample PCAP and detect at least 3 types of suspicious indicators (e.g., port scans, suspicious DNS, payload anomalies).
- Configurable via `config/ai_cyber_helper.json` and accessible via GUI tab and CLI.

Next steps
- Implement core module skeleton and create sample config.
- Add unit tests and sample data for vulnerability and network analysis.