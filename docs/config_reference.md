Configuration reference — `config/ai_cyber_helper.json`

Top-level keys
- enable_vuln_scan (bool): Enable local vulnerability scanning (default true)
- enable_network_analysis (bool): Enable network/pcap analysis (default true)

vuln_scan
- scan_timeout_seconds (int): Per-scan timeout in seconds (default 300)
- max_concurrent_scans (int): Number of concurrent TCP scans
- cve_db_path (string): Path to a local JSON CVE DB used for lookups (optional)
- use_online_cve_lookup (bool): If true, the system may query remote CVE feeds (opt-in)

network_analysis
- pcap_dir (string): Default directory to read/write PCAPs
- ingest_live_interface (bool): If true, allow live capture (disabled by default)
- flow_timeout_seconds (int): Flow aggregation timeout for heuristics

vuln_scan
- allow_public_targets (bool): If true, allow scanning public/non-private targets even when `scan_safe_mode` is enabled. This value can be set interactively from the GUI and will persist to `config/ai_cyber_helper.json` if the user chooses to remember their decision.
report
- output_dir (string): Directory where reports are written
- format (list): Preferred output formats, e.g., ["json", "html"]

logging
- level (string): Logging level, e.g., "INFO", "DEBUG"
- anonymize_ips (bool): If true, IPs in logs/reports will be redacted/anonymized

Notes
- Keep online lookups disabled for sensitive networks. Make sure you have consent to scan any targets.