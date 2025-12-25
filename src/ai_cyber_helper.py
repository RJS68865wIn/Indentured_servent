"""AI Cybersecurity Helper — Core module skeleton

Contains high-level interfaces for vulnerability scanning and network analysis.
"""
import json
import logging
import os
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

DEFAULT_CONFIG_PATH = os.path.join(os.path.dirname(__file__), '..', 'config', 'ai_cyber_helper.json')


class AiCyberHelper:
    def __init__(self, config_path: str = None):
        self.config_path = config_path or DEFAULT_CONFIG_PATH
        self.config = self._load_config(self.config_path)
        self._setup_logging()

    def _load_config(self, path: str) -> Dict[str, Any]:
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            logger.exception('Failed to load config, using defaults')
            return {}

    def save_config(self) -> bool:
        """Persist the current config back to disk (overwrites config file).

        Returns True on success, False on failure.
        """
        try:
            with open(self.config_path, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=2)
            logger.info('Saved config to %s', self.config_path)
            return True
        except Exception:
            logger.exception('Failed to save config')
            return False

    def reset_allow_public_targets(self) -> bool:
        """Reset the persisted `allow_public_targets` flag to False and save config."""
        try:
            self.config.setdefault('vuln_scan', {})['allow_public_targets'] = False
            return self.save_config()
        except Exception:
            logger.exception('Failed to reset allow_public_targets')
            return False

    def _setup_logging(self):
        level = self.config.get('logging', {}).get('level', 'INFO')
        logging.basicConfig(level=getattr(logging, level))

    def tcp_port_scan(self, host: str, ports: List[int], timeout: float = 1.0, max_workers: int | None = None) -> Dict[str, Any]:
        """Perform a simple TCP connect scan against `host` for the given `ports`.

        Uses configured defaults for concurrency and inter-port delay. Returns a dict: { 'host': host, 'open': [ { 'port': p, 'banner': '...' }, ... ] }
        """
        import socket
        import time
        from concurrent.futures import ThreadPoolExecutor, as_completed

        # Respect configured max workers if not provided
        if max_workers is None:
            max_workers = int(self.config.get('vuln_scan', {}).get('max_concurrent_scans', 4))
        delay_ms = int(self.config.get('vuln_scan', {}).get('scan_delay_ms', 0))

        logger.debug('Starting tcp_port_scan against %s ports=%s (max_workers=%s, delay_ms=%s)', host, ports, max_workers, delay_ms)

        def _check_port(port: int):
            result = {'port': port, 'open': False, 'banner': ''}
            try:
                # optional small delay to avoid aggressive scanning
                if delay_ms > 0:
                    time.sleep(delay_ms / 1000.0)
                with socket.create_connection((host, port), timeout=timeout) as s:
                    result['open'] = True
                    s.settimeout(0.5)
                    try:
                        banner = s.recv(1024)
                        if isinstance(banner, bytes):
                            banner = banner.decode('utf-8', errors='ignore').strip()
                        result['banner'] = banner
                    except Exception:
                        # No banner or read timed out
                        result['banner'] = ''
            except Exception:
                # Closed/filtered
                pass
            return result

        open_ports = []
        with ThreadPoolExecutor(max_workers=min(max_workers, len(ports) or 1)) as ex:
            futures = {ex.submit(_check_port, p): p for p in ports}
            for fut in as_completed(futures):
                r = fut.result()
                if r.get('open'):
                    open_ports.append(r)
        return {'host': host, 'open': sorted(open_ports, key=lambda x: x['port'])}

    def _lookup_cves(self, service: str, version: str = '') -> List[Dict[str, Any]]:
        """Lookup CVEs in a local CVE DB (simple JSON) by service name/version.

        Respects the `use_online_cve_lookup` flag; no online queries are performed by default.
        """
        db_path = self.config.get('vuln_scan', {}).get('cve_db_path') or self.config.get('vuln_scan', {}).get('cve_db.json')
        if not db_path or not os.path.exists(db_path):
            return []
        try:
            with open(db_path, 'r', encoding='utf-8') as f:
                db = json.load(f)
        except Exception:
            logger.exception('Failed to read CVE DB')
            return []

        # Simple matching: service name key, or substring match
        hits = []
        for key, entries in db.items():
            if key.lower() in service.lower() or service.lower() in key.lower():
                for e in entries:
                    # Optional version filter could be implemented here
                    hits.append(e)
        return hits

    def _is_private_address(self, host: str) -> bool:
        """Return True if host is a private/reserved address (IPv4)."""
        try:
            parts = host.split('.')
            if len(parts) != 4:
                return False
            nums = [int(p) for p in parts]
            a,b,c,_ = nums
            if a == 10:
                return True
            if a == 127:
                return True
            if a == 172 and 16 <= b <= 31:
                return True
            if a == 192 and b == 168:
                return True
            return False
        except Exception:
            return False

    def _anonymize_ip(self, ip: str) -> str:
        """Deterministically anonymize an IP address using a short hash."""
        try:
            import hashlib
            return 'anon-' + hashlib.sha256(ip.encode('utf-8')).hexdigest()[:8]
        except Exception:
            return 'anon'

    def _maybe_anonymize_report(self, report: Dict[str, Any]) -> Dict[str, Any]:
        if self.config.get('logging', {}).get('anonymize_ips'):
            # Replace host fields in report.targets and any host keys in issues
            for t in report.get('targets', []):
                h = t.get('host')
                if h:
                    t['host'] = self._anonymize_ip(h)
            for issue in report.get('issues', []):
                h = issue.get('host')
                if h:
                    issue['host'] = self._anonymize_ip(h)
        return report

    def scan_targets(self, targets: List[object], default_ports: List[int] = None) -> Dict[str, Any]:
        """Run local vulnerability scans on the provided targets.

        `targets` may be:
          - list of host strings (e.g. '127.0.0.1') using default ports
          - list of dicts: { 'host': '127.0.0.1', 'ports': [22,80] }

        Returns a report dict summarizing open services and any matched CVEs.
        """
        logger.info('scan_targets called for %s', targets)
        if default_ports is None:
            # Common ports to check if none given
            default_ports = [22, 80, 443, 3306, 5432, 8080]

        report = {'targets': [], 'issues': []}
        safe_mode = bool(self.config.get('vuln_scan', {}).get('scan_safe_mode', False))
        for t in targets:
            if isinstance(t, str):
                host = t
                ports = default_ports
            elif isinstance(t, dict):
                host = t.get('host')
                ports = t.get('ports', default_ports)
            else:
                continue

            # If safe mode is enabled, skip public/non-private addresses
            if safe_mode and not self._is_private_address(host):
                host_entry = {'host': host, 'skipped': True, 'reason': 'scan_safe_mode'}
                report['targets'].append(host_entry)
                continue

            scan_res = self.tcp_port_scan(host, ports)
            host_entry = {'host': host, 'open_ports': scan_res.get('open', [])}

            # For each open port, attempt to map to CVEs by banner
            for p in host_entry['open_ports']:
                banner = p.get('banner', '')
                cves = self._lookup_cves(banner)
                if cves:
                    issue = {
                        'host': host,
                        'port': p['port'],
                        'banner': banner,
                        'cves': cves,
                    }
                    report['issues'].append(issue)
            report['targets'].append(host_entry)

        report = self._maybe_anonymize_report(report)
        return report

    def analyze_network_traffic(self, pcap_path: str) -> Dict[str, Any]:
        """Analyze a pcap file and return findings.

        Strategy:
        - If `scapy` is available, attempt to parse the pcap and extract flows
          to detect port scans (many distinct dst ports from same src) and
          other heuristics.
        - Otherwise, fall back to a lightweight text-based parser that accepts
          simple CSV-like lines: "SRC,DST,PORT" (useful for tests and samples).
        """
        logger.info('analyze_network_traffic called for %s', pcap_path)
        if not os.path.exists(pcap_path):
            logger.warning('PCAP path does not exist: %s', pcap_path)
            return {'pcap': pcap_path, 'findings': [], 'error': 'not_found'}

        size = os.path.getsize(pcap_path)
        findings: List[Dict[str, Any]] = []

        # Try to use scapy for real pcap parsing when available
        try:
            from scapy.all import rdpcap, IP, DNS, UDP, TCP
            logger.debug('scapy available, parsing pcap with rdpcap')
            packets = rdpcap(pcap_path)
            flows = {}
            dns_queries = []
            host_to_ports = {}
            timestamps = []

            for p in packets:
                ts = float(getattr(p, 'time', 0) or 0)
                timestamps.append(ts)
                if IP in p:
                    src = p[IP].src
                    dst = p[IP].dst
                    dport = None
                    proto = None
                    if p.haslayer(TCP):
                        proto = 'TCP'
                        try:
                            dport = int(p[TCP].dport)
                        except Exception:
                            dport = None
                    elif p.haslayer(UDP):
                        proto = 'UDP'
                        try:
                            dport = int(p[UDP].dport)
                        except Exception:
                            dport = None

                    key = (src, dst)
                    host_to_ports.setdefault((src, dst), set())
                    if dport:
                        host_to_ports[(src, dst)].add(dport)
                    flows.setdefault(key, []).append({'port': dport, 'time': ts, 'proto': proto})

                # DNS parsing for queries (if present)
                if DNS in p:
                    try:
                        qd = p[DNS].qd
                        if qd is not None:
                            qname = qd.qname.decode('utf-8', errors='ignore').rstrip('.')
                            qtype = qd.qtype
                            dns_queries.append({'time': ts, 'src': p[IP].src if IP in p else None, 'qname': qname, 'qtype': qtype})
                    except Exception:
                        pass

            # Port-scan heuristic: many distinct dst ports from same source to same dest
            for (src, dst), ports in host_to_ports.items():
                uniq = len(ports)
                if uniq >= 10:
                    findings.append({
                        'type': 'port_scan',
                        'src': src,
                        'dst': dst,
                        'unique_dst_ports': uniq,
                        'severity': 'high',
                        'note': 'multiple destination ports observed in pcap'
                    })

            # DNS anomaly heuristic: many distinct domains or suspicious TLDs in short time
            if dns_queries:
                domains = [d['qname'] for d in dns_queries if d.get('qname')]
                # quick heuristics
                distinct = len(set(domains))
                short_window = (max(timestamps) - min(timestamps)) if timestamps else 0
                if distinct >= 20 and short_window <= 60:
                    findings.append({
                        'type': 'dns_flood',
                        'count': distinct,
                        'severity': 'high',
                        'note': 'many distinct DNS queries in short time'
                    })
                # suspicious auto-generated domain pattern detection (e.g., short TTL or random-looking)
                random_like = sum(1 for d in domains if len(d.split('.')) and len(d.split('.')[0]) >= 12)
                if random_like >= 5:
                    findings.append({
                        'type': 'suspicious_dns_pattern',
                        'count': random_like,
                        'severity': 'medium',
                        'note': 'possible DGA or random-looking domains observed in DNS queries'
                    })

            # Beaconing detection: look for periodic connections from same src to same dst across time
            for (src, dst), events in flows.items():
                times = sorted([e['time'] for e in events if e['time']])
                if len(times) >= 5:
                    # compute inter-arrival times and check if they are roughly periodic
                    diffs = [round(times[i+1]-times[i], 2) for i in range(len(times)-1)]
                    if diffs:
                        avg = sum(diffs)/len(diffs)
                        # consider periodic if std dev is relatively small compared to mean
                        import statistics
                        stdev = statistics.pstdev(diffs) if len(diffs) > 1 else 0
                        if avg > 0 and stdev/avg < 0.25:
                            findings.append({
                                'type': 'beaconing',
                                'src': src,
                                'dst': dst,
                                'interval_avg': avg,
                                'count': len(times),
                                'severity': 'high',
                                'note': 'regular periodic connections observed (possible C2 beaconing)'
                            })

            return {'pcap': pcap_path, 'size': size, 'findings': findings}
        except Exception as e:
            logger.debug('scapy not available or parsing failed (%s), falling back to text parser', e)

        # Fallback: simple text-based parser (lines like SRC,DST,PORT or SRC,DST,PORT,TIMESTAMP or DNS,QNAME)
        try:
            counts = {}
            dns_q = []
            flows = {}
            with open(pcap_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    parts = line.strip().split(',')
                    if not parts:
                        continue
                    if parts[0].lower() == 'dns' and len(parts) >= 3:
                        # Format: DNS,SRC,QNAME
                        _, src, qname = parts[:3]
                        dns_q.append({'src': src.strip(), 'qname': qname.strip()})
                        continue
                    if len(parts) < 3:
                        continue
                    src, dst, port = parts[0].strip(), parts[1].strip(), parts[2].strip()
                    try:
                        port = int(port)
                    except Exception:
                        continue
                    key = (src, dst)
                    flows.setdefault(key, []).append(port)

            for (src, dst), ports in flows.items():
                if len(set(ports)) >= 5:  # lower threshold for text-based samples
                    findings.append({
                        'type': 'port_scan',
                        'src': src,
                        'dst': dst,
                        'unique_dst_ports': len(set(ports)),
                        'severity': 'medium',
                        'note': 'multiple destination ports observed in sample text pcap'
                    })

            # DNS text heuristics
            if dns_q:
                domains = [d['qname'] for d in dns_q]
                if len(set(domains)) >= 10:
                    findings.append({'type': 'dns_flood', 'count': len(set(domains)), 'severity': 'high'})
                random_like = sum(1 for d in domains if len(d.split('.')[0]) >= 12)
                if random_like >= 3:
                    findings.append({'type': 'suspicious_dns_pattern', 'count': random_like, 'severity': 'medium'})

            # Simple beaconing detection using port occurrence intervals - need timestamps for real detection; use repeated patterns by count
            for (src, dst), ports in flows.items():
                if len(ports) >= 8 and len(set(ports)) <= 3:
                    findings.append({'type': 'possible_beaconing', 'src': src, 'dst': dst, 'count': len(ports), 'severity': 'medium'})
        except Exception:
            logger.exception('Failed to parse pcap fallback')

        # Always include very-small-file heuristic for quick sanity checks
        if size < 100 and not findings:
            findings.append({'type': 'small_pcap', 'severity': 'low', 'note': 'very small pcap file'})

        return {'pcap': pcap_path, 'size': size, 'findings': findings}

    def suggest_mitigation(self, finding: Dict[str, Any]) -> List[str]:
        """Suggest mitigation steps for a finding."""
        severity = finding.get('severity', 'low')
        if severity == 'critical':
            return ['Isolate system', 'Apply known patch', 'Block malicious IPs']
        if severity == 'high':
            return ['Apply patch', 'Investigate service']
        return ['Monitor', 'Investigate further']

    def report_results(self, report: Dict[str, Any], out_path: str = None) -> str:
        """Write report to disk and return path."""
        # Apply anonymization if configured
        report = self._maybe_anonymize_report(report)

        out_dir = out_path or self.config.get('report', {}).get('output_dir', 'data/reports')
        os.makedirs(out_dir, exist_ok=True)
        report_path = os.path.join(out_dir, 'ai_cyber_report.json')
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)
        logger.info('Wrote report to %s', report_path)
        return report_path


if __name__ == '__main__':
    # Minimal CLI example
    import argparse

    parser = argparse.ArgumentParser(description='AI Cybersecurity Helper')
    parser.add_argument('--config', help='Path to config JSON')
    parser.add_argument('--scan', nargs='*', help='Targets to scan (hosts/IPs)')
    parser.add_argument('--pcap', help='PCAP file to analyze')
    args = parser.parse_args()

    helper = AiCyberHelper(config_path=args.config)

    if args.scan:
        report = helper.scan_targets(args.scan)
        helper.report_results(report)
    elif args.pcap:
        findings = helper.analyze_network_traffic(args.pcap)
        helper.report_results(findings)
    else:
        parser.print_help()