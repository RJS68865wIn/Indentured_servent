import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import threading
import json
import os
from typing import Optional

from src.ai_cyber_helper import AiCyberHelper


class CyberHelperTab:
    """GUI tab for the AI Cybersecurity Helper"""

    def __init__(self, notebook):
        self.frame = ttk.Frame(notebook)
        self.helper = AiCyberHelper()
        self._build_ui()

    def _build_ui(self):
        # Top controls frame
        ctrl = ttk.Frame(self.frame)
        ctrl.pack(fill=tk.X, padx=8, pady=8)

        ttk.Label(ctrl, text="Targets (comma-separated hosts):").pack(side=tk.LEFT, padx=(0, 6))
        self.targets_entry = ttk.Entry(ctrl, width=60)
        self.targets_entry.pack(side=tk.LEFT, padx=(0, 6))

        self.scan_btn = ttk.Button(ctrl, text="Scan Targets", command=self._on_scan_targets)
        self.scan_btn.pack(side=tk.LEFT, padx=(0, 6))

        # Allow public targets override (default off). When safe mode is enabled in config,
        # public/non-private targets will be skipped unless the user confirms or checks this box.
        self.allow_public_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(ctrl, text="Allow public targets", variable=self.allow_public_var).pack(side=tk.LEFT, padx=(0, 6))

        ttk.Separator(self.frame, orient=tk.HORIZONTAL).pack(fill=tk.X, padx=8, pady=6)

        # PCAP analysis controls
        pcap_ctrl = ttk.Frame(self.frame)
        pcap_ctrl.pack(fill=tk.X, padx=8, pady=4)

        ttk.Label(pcap_ctrl, text="PCAP / Sample file:").pack(side=tk.LEFT, padx=(0, 6))
        self.pcap_path_var = tk.StringVar()
        self.pcap_entry = ttk.Entry(pcap_ctrl, textvariable=self.pcap_path_var, width=50)
        self.pcap_entry.pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(pcap_ctrl, text="Browse", command=self._browse_pcap).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(pcap_ctrl, text="Analyze PCAP", command=self._on_analyze_pcap).pack(side=tk.LEFT)

        ttk.Separator(self.frame, orient=tk.HORIZONTAL).pack(fill=tk.X, padx=8, pady=6)

        # Results area
        self.results = scrolledtext.ScrolledText(self.frame, height=16, wrap=tk.WORD)
        self.results.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 8))

        # Status row
        status_row = ttk.Frame(self.frame)
        status_row.pack(fill=tk.X, padx=8, pady=(0, 4))
        self.status_label = ttk.Label(status_row, text="Idle")
        self.status_label.pack(side=tk.LEFT)

        # Consent indicator & quick reset
        self._consent_var = tk.StringVar(value='Public scans: Allowed' if self.helper.config.get('vuln_scan', {}).get('allow_public_targets') else 'Public scans: Not allowed')
        self.consent_label = ttk.Label(status_row, textvariable=self._consent_var)
        self.consent_label.pack(side=tk.LEFT, padx=(8, 6))
        ttk.Button(status_row, text='Reset remembered consent', command=self._quick_reset_consent).pack(side=tk.LEFT)

    def _set_status(self, text: str):
        self.status_label.config(text=text)

    def _append_results(self, text: str):
        self.results.insert(tk.END, text + "\n")
        self.results.see(tk.END)

    def _update_consent_indicator(self):
        allowed = bool(self.helper.config.get('vuln_scan', {}).get('allow_public_targets'))
        self._consent_var.set('Public scans: Allowed' if allowed else 'Public scans: Not allowed')

    def _quick_reset_consent(self):
        ok = self.helper.reset_allow_public_targets()
        self._update_consent_indicator()
        self._append_results(f'Reset remembered consent (ok={ok})')

    def _browse_pcap(self):
        path = filedialog.askopenfilename(title='Select PCAP or sample file', filetypes=[('All files', '*.*')])
        if path:
            self.pcap_path_var.set(path)

    def _on_scan_targets(self):
        raw = self.targets_entry.get().strip()
        if not raw:
            self._append_results('No targets provided')
            return
        targets = [t.strip() for t in raw.split(',') if t.strip()]

        # Check for safe-mode and public targets
        safe_mode = bool(self.helper.config.get('vuln_scan', {}).get('scan_safe_mode', False))
        public_targets = [t for t in targets if not self.helper._is_private_address(t)]

        # If user already remembered a choice in config, respect it
        remembered = bool(self.helper.config.get('vuln_scan', {}).get('allow_public_targets', False))
        if safe_mode and public_targets and not (self.allow_public_var.get() or remembered):
            # Use a custom dialog so the user can "remember" the choice
            proceed, remember = self._confirm_public_targets(public_targets)
            if remember:
                # Persist choice to config
                self.helper.config.setdefault('vuln_scan', {})['allow_public_targets'] = proceed
                saved = self.helper.save_config()
                self._append_results(f"Remembered choice: allow_public_targets={proceed} (saved={saved})")
            if not proceed:
                # remove public targets
                targets = [t for t in targets if self.helper._is_private_address(t)]
                self._append_results(f"Skipped public targets: {', '.join(public_targets)}")
                if not targets:
                    self._append_results('No targets to scan after skipping public targets.')
                    return

        self._set_status('Scanning targets...')
        self.scan_btn.config(state=tk.DISABLED)
        threading.Thread(target=self._do_scan_targets, args=(targets,), daemon=True).start()

    def _do_scan_targets(self, targets):
        try:
            report = self.helper.scan_targets(targets)
            text = json.dumps(report, indent=2)
            self._append_results('Scan complete:')
            self._append_results(text)
        except Exception as e:
            self._append_results(f'Error during scan: {e}')
        finally:
            self.scan_btn.config(state=tk.NORMAL)
            self._set_status('Idle')

    def _on_analyze_pcap(self):
        path = self.pcap_path_var.get().strip()
        if not path:
            self._append_results('No PCAP provided')
            return
        if not os.path.exists(path):
            self._append_results(f'File not found: {path}')
            return
        self._set_status('Analyzing PCAP...')
        threading.Thread(target=self._do_analyze_pcap, args=(path,), daemon=True).start()

    def _do_analyze_pcap(self, path: str):
        try:
            res = self.helper.analyze_network_traffic(path)
            self._append_results('PCAP analysis complete:')
            self._append_results(json.dumps(res, indent=2))
        except Exception as e:
            self._append_results(f'Error during PCAP analysis: {e}')
        finally:
            self._set_status('Idle')

    def _confirm_public_targets(self, public_targets):
        """Custom modal dialog: returns (proceed:bool, remember:bool)"""
        dlg = tk.Toplevel(self.frame)
        dlg.title('Confirm public targets')
        dlg.transient(self.frame)
        dlg.grab_set()

        msg = tk.Label(dlg, text=("Safe mode is enabled. The following public/non-private targets were detected:\n\n"
                                   + ", ".join(public_targets)
                                   + "\n\nProceed scanning them?"), justify=tk.LEFT, wraplength=500)
        msg.pack(padx=12, pady=(12, 6))

        remember_var = tk.BooleanVar(value=False)
        cb = ttk.Checkbutton(dlg, text='Remember my choice (persist to config)', variable=remember_var)
        cb.pack(padx=12, pady=(0, 12))

        res = {'proceed': False}

        def do_proceed():
            res['proceed'] = True
            dlg.destroy()

        def do_skip():
            res['proceed'] = False
            dlg.destroy()

        btn_frame = ttk.Frame(dlg)
        btn_frame.pack(padx=12, pady=(0, 12))
        ttk.Button(btn_frame, text='Proceed', command=do_proceed).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(btn_frame, text='Skip', command=do_skip).pack(side=tk.LEFT)

        dlg.wait_window()
        return res.get('proceed', False), bool(remember_var.get())