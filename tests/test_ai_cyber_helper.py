import os
import json
import socketserver
import threading
from src.ai_cyber_helper import AiCyberHelper


def test_load_config_default():
    helper = AiCyberHelper()
    assert isinstance(helper.config, dict)


def test_tcp_port_scan_detects_open_port():
    # Start a temporary TCP server that sends a banner
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            try:
                self.request.sendall(b'FAKE-SERVICE-1.0')
            except Exception:
                pass

    server = socketserver.TCPServer(('127.0.0.1', 0), Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        helper = AiCyberHelper()
        res = helper.tcp_port_scan('127.0.0.1', [port], timeout=1.0)
        assert 'open' in res
        open_ports = res['open']
        assert len(open_ports) == 1
        assert open_ports[0]['port'] == port
        assert 'FAKE-SERVICE' in open_ports[0].get('banner', '')
    finally:
        server.shutdown()
        server.server_close()


def test_lookup_cves_reads_db(tmp_path):
    # Create a tiny CVE DB and point config to it
    cve_db = {
        "FakeService": [{"cve": "CVE-9999-0001", "summary": "Test", "severity": "low"}]
    }
    cve_path = tmp_path / 'cve_db.json'
    cve_path.write_text(json.dumps(cve_db))

    cfg = {"vuln_scan": {"cve_db_path": str(cve_path)}}
    cfg_path = tmp_path / 'cfg.json'
    cfg_path.write_text(json.dumps(cfg))

    helper = AiCyberHelper(config_path=str(cfg_path))
    hits = helper._lookup_cves('FakeService 1.0')
    assert isinstance(hits, list)
    assert hits and hits[0]['cve'] == 'CVE-9999-0001'


def test_scan_safe_mode_skips_public(tmp_path):
    cfg = {"vuln_scan": {"scan_safe_mode": True}}
    cfg_path = tmp_path / 'cfg.json'
    cfg_path.write_text(json.dumps(cfg))

    helper = AiCyberHelper(config_path=str(cfg_path))
    report = helper.scan_targets(['8.8.8.8', '10.0.0.5'])
    targets = report.get('targets', [])
    skip = next((t for t in targets if t.get('host') == '8.8.8.8'), None)
    ok = next((t for t in targets if t.get('host') == '10.0.0.5'), None)
    assert skip and skip.get('skipped') is True
    assert ok and ok.get('skipped') is not True


def test_anonymize_report(tmp_path):
    cfg = {"logging": {"anonymize_ips": True}, "report": {"output_dir": str(tmp_path)}}
    cfg_path = tmp_path / 'cfg.json'
    cfg_path.write_text(json.dumps(cfg))

    from src.ai_cyber_helper import AiCyberHelper
    helper = AiCyberHelper(config_path=str(cfg_path))
    report = {'targets': [{'host': '127.0.0.1', 'open_ports': []}], 'issues': []}
    out = helper.report_results(report, out_path=str(tmp_path))
    with open(out, 'r', encoding='utf-8') as f:
        data = json.load(f)
    assert '127.0.0.1' not in json.dumps(data)
    assert 'anon-' in json.dumps(data)


def test_detect_port_scan_in_text_pcap(tmp_path):
    # Create a pseudo-pcap (CSV) that simulates multiple ports from a single source
    src = '10.0.0.5'
    dst = '10.0.0.1'
    p = tmp_path / 'portscan.txt'
    lines = [f"{src},{dst},{port}\n" for port in range(20, 30)]
    p.write_text(''.join(lines))
    helper = AiCyberHelper()
    res = helper.analyze_network_traffic(str(p))
    findings = res.get('findings', [])
    assert any(f.get('type') == 'port_scan' and f.get('src') == src and f.get('dst') == dst for f in findings)


def test_detect_dns_flood_sample(tmp_path):
    src = '10.0.0.5'
    p = tmp_path / 'dns_flood.txt'
    p.write_text('\n'.join([f"DNS,{src},d{i}example.com" for i in range(15)]))
    helper = AiCyberHelper()
    res = helper.analyze_network_traffic(str(p))
    findings = res.get('findings', [])
    assert any(f.get('type') == 'dns_flood' for f in findings)


def test_detect_beaconing_sample(tmp_path):
    # Create a pseudo-pcap with repeated events (timestamps in 4th column)
    src = '10.0.0.8'
    dst = '10.0.0.50'
    p = tmp_path / 'beaconing.txt'
    lines = [f"{src},{dst},443,{i*60}\n" for i in range(8)]
    p.write_text(''.join(lines))
    helper = AiCyberHelper()
    res = helper.analyze_network_traffic(str(p))
    findings = res.get('findings', [])
    assert any(f.get('type') in ('beaconing','possible_beaconing') and f.get('src') == src for f in findings)


def test_analyze_network_traffic_small_file(tmp_path):
    p = tmp_path / 'small.pcap'
    p.write_text('pcap')
    helper = AiCyberHelper()
    res = helper.analyze_network_traffic(str(p))
    assert res.get('size', 0) < 100
    assert any(f.get('type') == 'small_pcap' for f in res.get('findings', []))


def test_report_results_writes(tmp_path):
    helper = AiCyberHelper()
    report = {'targets': ['127.0.0.1'], 'issues': []}
    out = helper.report_results(report, out_path=str(tmp_path))
    assert os.path.exists(out)
    with open(out, 'r', encoding='utf-8') as f:
        data = json.load(f)
    assert data['targets'] == ['127.0.0.1']