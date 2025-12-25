#!/usr/bin/env python3
"""Cross-platform launcher that auto-activates/uses a local .venv if present.

Usage:
  python scripts/run_cyber_helper.py gui
  python scripts/run_cyber_helper.py scan 127.0.0.1 10.0.0.5
  python scripts/run_cyber_helper.py pcap data/sample_inputs/portscan.txt
"""
import argparse
import json
import os
import sys
import subprocess

VENV_DIR = os.path.join(os.getcwd(), '.venv')
VENV_ENV_FLAG = 'RUN_CYBER_HELPER_IN_VENV'


def find_venv_python():
    if not os.path.isdir(VENV_DIR):
        return None
    if os.name == 'nt':
        candidate = os.path.join(VENV_DIR, 'Scripts', 'python.exe')
    else:
        candidate = os.path.join(VENV_DIR, 'bin', 'python')
    return candidate if os.path.exists(candidate) else None


def maybe_reexec_in_venv():
    # If a venv python exists and we're not already running inside it, re-exec
    venv_py = find_venv_python()
    if not venv_py:
        return
    cur = os.path.abspath(sys.executable)
    venv_py_abs = os.path.abspath(venv_py)
    if cur == venv_py_abs or os.environ.get(VENV_ENV_FLAG) == '1':
        return
    # Re-exec using venv python, pass through args and set flag to avoid loops
    os.environ[VENV_ENV_FLAG] = '1'
    try:
        os.execv(venv_py_abs, [venv_py_abs] + sys.argv)
    except Exception:
        # Fallback: spawn subprocess
        subprocess.check_call([venv_py_abs] + sys.argv)
        sys.exit(0)


def run_gui():
    # Prefer to launch via module to keep behavior consistent
    subprocess.check_call([sys.executable, '-m', 'src.main'])


def run_scan(hosts):
    from src.ai_cyber_helper import AiCyberHelper
    helper = AiCyberHelper()
    report = helper.scan_targets(hosts)
    print(json.dumps(report, indent=2))


def run_pcap(path):
    from src.ai_cyber_helper import AiCyberHelper
    helper = AiCyberHelper()
    res = helper.analyze_network_traffic(path)
    print(json.dumps(res, indent=2))


def main(argv=None):
    argv = argv or sys.argv[1:]
    maybe_reexec_in_venv()

    parser = argparse.ArgumentParser(prog='run_cyber_helper')
    subparsers = parser.add_subparsers(dest='cmd')

    subparsers.add_parser('gui', help='Start the GUI')
    scan_parser = subparsers.add_parser('scan', help='Run quick TCP connect scan')
    scan_parser.add_argument('hosts', nargs='+')
    pcap_parser = subparsers.add_parser('pcap', help='Analyze a pcap or sample file')
    pcap_parser.add_argument('path')

    args = parser.parse_args(argv)
    if args.cmd == 'gui':
        run_gui()
        return
    if args.cmd == 'scan':
        run_scan(args.hosts)
        return
    if args.cmd == 'pcap':
        run_pcap(args.path)
        return

    parser.print_help()


if __name__ == '__main__':
    main()
