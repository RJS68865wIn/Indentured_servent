Usage — AI Cybersecurity Helper

Quickstart (CLI)
- Run a local vulnerability scan:
  - python -m src.ai_cyber_helper --scan 127.0.0.1
  - python -m src.ai_cyber_helper --scan 127.0.0.1 192.168.1.10
  - For hosts with custom ports: pass as dicts via a small wrapper script or use the GUI

- Analyze a PCAP (or text sample):
  - python -m src.ai_cyber_helper --pcap data/sample_inputs/portscan.txt
  - PCAP files parsed with scapy (if installed) or a text fallback (CSV lines: SRC,DST,PORT[,TIMESTAMP])

GUI Quickstart
- Start the GUI (project main window) and open the "🛡️ Cyber Helper" tab.
- Targets: Enter comma-separated hosts (e.g., 127.0.0.1, 10.0.0.5) and click "Scan Targets".
- PCAP: Browse to a sample or real pcap, click "Analyze PCAP" and review findings in the results panel.

Reports
- By default, reports are written to the configured `report.output_dir` (see `config/ai_cyber_helper.json`).
- Report keys include: `targets`, `issues` (host/port/CVE entries), `pcap`, `findings` (network anomalies).

Security & privacy
- All analysis is local by default. Online lookups (e.g., CVE database, reputation services) are opt-in in the config.
- Be careful scanning networks you do not own; the scanner does TCP connect checks only (no exploits).

Tips
- Use `data/sample_inputs/` for safe sample files when experimenting.
- Install `scapy` to analyze real PCAP files; otherwise, use the text sample format for tests and demos.