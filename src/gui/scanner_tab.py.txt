"""
Security Scanner Tab - GUI for running security scans
"""
import tkinter as tk
from tkinter import ttk, messagebox
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any

from ..security_scanner import WindowsSecurityScanner, ScanResult
from ..utils.logger import setup_logger

class ScannerTab:
    """Security Scanner tab for running various security scans"""
    
    def __init__(self, parent):
        self.parent = parent
        self.frame = ttk.Frame(parent)
        
        # Initialize scanner and logger
        self.scanner = WindowsSecurityScanner()
        self.logger = setup_logger("ScannerGUI")
        
        # Scan results storage
        self.current_scan = None
        self.scan_history = []
        
        # Create widgets
        self._create_widgets()
        
        # Load scan history
        self._load_scan_history()
    
    def _create_widgets(self):
        """Create scanner tab widgets"""
        # Main container with two panes
        main_paned = ttk.PanedWindow(self.frame, orient=tk.HORIZONTAL)
        main_paned.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Left pane - Scan controls
        left_frame = ttk.Frame(main_paned)
        main_paned.add(left_frame, weight=1)
        
        # Right pane - Results display
        right_frame = ttk.Frame(main_paned)
        main_paned.add(right_frame, weight=2)
        
        # ===== LEFT PANE - SCAN CONTROLS =====
        
        # Scan Type Selection
        scan_type_frame = ttk.LabelFrame(left_frame, text="Scan Type", padding=20)
        scan_type_frame.pack(fill=tk.X, pady=(0, 20))
        
        # Scan type radio buttons
        self.scan_type_var = tk.StringVar(value="quick")
        
        scan_types = [
            ("quick", "🛡️ Quick Scan", "Scans common threat locations (2-5 min)"),
            ("full", "🔍 Full System Scan", "Comprehensive system scan (30-60 min)"),
            ("memory", "🧠 Memory Scan", "Scan running processes and memory"),
            ("network", "🌐 Network Scan", "Scan network shares and connections"),
            ("custom", "⚙️ Custom Scan", "Scan specific folders")
        ]
        
        for scan_id, name, description in scan_types:
            radio = ttk.Radiobutton(
                scan_type_frame,
                text=name,
                value=scan_id,
                variable=self.scan_type_var,
                command=self._on_scan_type_changed
            )
            radio.pack(anchor=tk.W, pady=5)
            
            desc_label = ttk.Label(
                scan_type_frame,
                text=description,
                font=("Segoe UI", 9),
                foreground="#6B7280"
            )
            desc_label.pack(anchor=tk.W, padx=20, pady=(0, 10))
        
        # Custom scan path selection (hidden by default)
        self.custom_scan_frame = ttk.Frame(scan_type_frame)
        
        custom_label = ttk.Label(
            self.custom_scan_frame,
            text="Select folders to scan:",
            font=("Segoe UI", 10)
        )
        custom_label.pack(anchor=tk.W, pady=(10, 5))
        
        # Listbox for selected paths
        self.custom_paths_listbox = tk.Listbox(
            self.custom_scan_frame,
            height=4,
            selectmode=tk.EXTENDED
        )
        self.custom_paths_listbox.pack(fill=tk.X, pady=5)
        
        # Buttons for path management
        path_buttons_frame = ttk.Frame(self.custom_scan_frame)
        path_buttons_frame.pack(fill=tk.X)
        
        ttk.Button(
            path_buttons_frame,
            text="Add Folder",
            command=self._add_custom_folder,
            width=12
        ).pack(side=tk.LEFT, padx=(0, 5))
        
        ttk.Button(
            path_buttons_frame,
            text="Add File",
            command=self._add_custom_file,
            width=12
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            path_buttons_frame,
            text="Remove",
            command=self._remove_custom_path,
            width=12
        ).pack(side=tk.LEFT, padx=(5, 0))
        
        # Scan Options
        options_frame = ttk.LabelFrame(left_frame, text="Scan Options", padding=20)
        options_frame.pack(fill=tk.X, pady=(0, 20))
        
        # Save report option
        self.save_report_var = tk.BooleanVar(value=True)
        save_check = ttk.Checkbutton(
            options_frame,
            text="Save scan report",
            variable=self.save_report_var
        )
        save_check.pack(anchor=tk.W, pady=5)
        
        # Show detailed results
        self.detailed_results_var = tk.BooleanVar(value=True)
        detail_check = ttk.Checkbutton(
            options_frame,
            text="Show detailed results",
            variable=self.detailed_results_var
        )
        detail_check.pack(anchor=tk.W, pady=5)
        
        # Auto-clean threats
        self.auto_clean_var = tk.BooleanVar(value=False)
        clean_check = ttk.Checkbutton(
            options_frame,
            text="Auto-clean low severity threats",
            variable=self.auto_clean_var
        )
        clean_check.pack(anchor=tk.W, pady=5)
        
        # Scan Buttons
        button_frame = ttk.Frame(left_frame)
        button_frame.pack(fill=tk.X)
        
        # Start Scan Button (large and prominent)
        self.scan_button = ttk.Button(
            button_frame,
            text="🚀 START SCAN",
            command=self._start_scan,
            bootstyle="success",
            width=20
        )
        self.scan_button.pack(pady=(0, 10))
        
        # Stop Scan Button (disabled initially)
        self.stop_button = ttk.Button(
            button_frame,
            text="⏹️ STOP SCAN",
            command=self._stop_scan,
            bootstyle="danger",
            width=20,
            state=tk.DISABLED
        )
        self.stop_button.pack(pady=10)
        
        # Quick Action Buttons
        quick_frame = ttk.LabelFrame(left_frame, text="Quick Actions", padding=15)
        quick_frame.pack(fill=tk.X)
        
        quick_actions = [
            ("🔄 Check Updates", self._check_updates),
            ("🔥 Firewall Status", self._check_firewall),
            ("🛡️ Defender Status", self._check_defender),
            ("📊 View Reports", self._view_reports)
        ]
        
        for text, command in quick_actions:
            btn = ttk.Button(
                quick_frame,
                text=text,
                command=command,
                bootstyle="outline",
                width=18
            )
            btn.pack(pady=5)
        
        # ===== RIGHT PANE - RESULTS DISPLAY =====
        
        # Notebook for different result views
        self.results_notebook = ttk.Notebook(right_frame)
        self.results_notebook.pack(fill=tk.BOTH, expand=True)
        
        # Summary Tab
        self.summary_frame = ttk.Frame(self.results_notebook)
        self.results_notebook.add(self.summary_frame, text="📊 Summary")
        
        # Threats Tab
        self.threats_frame = ttk.Frame(self.results_notebook)
        self.results_notebook.add(self.threats_frame, text="🔴 Threats")
        
        # Details Tab
        self.details_frame = ttk.Frame(self.results_notebook)
        self.results_notebook.add(self.details_frame, text="📋 Details")
        
        # History Tab
        self.history_frame = ttk.Frame(self.results_notebook)
        self.results_notebook.add(self.history_frame, text="📜 History")
        
        # Initialize all tabs
        self._init_summary_tab()
        self._init_threats_tab()
        self._init_details_tab()
        self._init_history_tab()
        
        # Progress bar at bottom
        self.progress_frame = ttk.Frame(right_frame)
        self.progress_frame.pack(fill=tk.X, pady=(10, 0))
        
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(
            self.progress_frame,
            variable=self.progress_var,
            mode='determinate',
            length=400
        )
        self.progress_bar.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        
        self.progress_label = ttk.Label(
            self.progress_frame,
            text="Ready",
            font=("Segoe UI", 10)
        )
        self.progress_label.pack(side=tk.RIGHT)
    
    def _init_summary_tab(self):
        """Initialize summary tab"""
        # Summary container
        summary_container = ttk.Frame(self.summary_frame)
        summary_container.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Welcome message
        welcome_label = ttk.Label(
            summary_container,
            text="🔒 Security Scanner",
            font=("Segoe UI", 24, "bold")
        )
        welcome_label.pack(anchor=tk.W, pady=(0, 10))
        
        self.summary_text = ttk.Label(
            summary_container,
            text="No scan results yet. Run a scan to see security analysis.",
            font=("Segoe UI", 12),
            wraplength=600
        )
        self.summary_text.pack(anchor=tk.W, pady=(0, 30))
        
        # Stats grid
        stats_frame = ttk.Frame(summary_container)
        stats_frame.pack(fill=tk.X, pady=20)
        
        self.stat_widgets = {}
        stats = [
            ("threats", "🔴 Threats Found", "0", "#EF4444"),
            ("warnings", "⚠️ Warnings", "0", "#F59E0B"),
            ("scanned", "📁 Items Scanned", "0", "#3B82F6"),
            ("duration", "⏱️ Scan Duration", "0s", "#10B981")
        ]
        
        for i, (key, label, value, color) in enumerate(stats):
            stat_frame = ttk.Frame(stats_frame)
            stat_frame.grid(row=i//2, column=i%2, padx=20, pady=10, sticky="nsew")
            
            # Configure grid weights
            stats_frame.grid_columnconfigure(0, weight=1)
            stats_frame.grid_columnconfigure(1, weight=1)
            
            label_widget = ttk.Label(
                stat_frame,
                text=label,
                font=("Segoe UI", 10),
                foreground="#6B7280"
            )
            label_widget.pack(anchor=tk.W)
            
            value_widget = ttk.Label(
                stat_frame,
                text=value,
                font=("Segoe UI", 24, "bold"),
                foreground=color
            )
            value_widget.pack(anchor=tk.W)
            
            self.stat_widgets[key] = value_widget
        
        # Recommendations section
        rec_frame = ttk.LabelFrame(summary_container, text="💡 Recommendations", padding=20)
        rec_frame.pack(fill=tk.X, pady=20)
        
        self.recommendations_text = tk.Text(
            rec_frame,
            height=6,
            font=("Segoe UI", 10),
            wrap=tk.WORD,
            bg="#1F2937",
            fg="white",
            relief=tk.FLAT
        )
        self.recommendations_text.pack(fill=tk.X)
        self.recommendations_text.insert("1.0", "Run a scan to get recommendations.")
        self.recommendations_text.config(state=tk.DISABLED)
    
    def _init_threats_tab(self):
        """Initialize threats tab"""
        # Threats container
        threats_container = ttk.Frame(self.threats_frame)
        threats_container.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Threats listbox with scrollbar
        list_frame = ttk.Frame(threats_container)
        list_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create treeview for threats
        columns = ("Severity", "Name", "Type", "Path")
        self.threats_tree = ttk.Treeview(
            list_frame,
            columns=columns,
            show="tree headings",
            height=15
        )
        
        # Configure columns
        self.threats_tree.heading("#0", text="", anchor=tk.W)
        self.threats_tree.column("#0", width=0, stretch=False)
        
        for col in columns:
            self.threats_tree.heading(col, text=col, anchor=tk.W)
            self.threats_tree.column(col, anchor=tk.W, width=150)
        
        # Add scrollbar
        tree_scroll = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.threats_tree.yview)
        self.threats_tree.configure(yscrollcommand=tree_scroll.set)
        
        # Pack treeview and scrollbar
        self.threats_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Threat details panel
        detail_frame = ttk.LabelFrame(threats_container, text="Threat Details", padding=15)
        detail_frame.pack(fill=tk.X, pady=(20, 0))
        
        self.threat_detail_text = tk.Text(
            detail_frame,
            height=8,
            font=("Segoe UI", 10),
            wrap=tk.WORD,
            bg="#1F2937",
            fg="white",
            relief=tk.FLAT
        )
        self.threat_detail_text.pack(fill=tk.X)
        self.threat_detail_text.insert("1.0", "Select a threat to view details.")
        self.threat_detail_text.config(state=tk.DISABLED)
        
        # Action buttons
        action_frame = ttk.Frame(threats_container)
        action_frame.pack(fill=tk.X, pady=(10, 0))
        
        ttk.Button(
            action_frame,
            text="🗑️ Remove Threat",
            command=self._remove_threat,
            bootstyle="danger",
            width=15
        ).pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Button(
            action_frame,
            text="📋 Copy Details",
            command=self._copy_threat_details,
            width=15
        ).pack(side=tk.LEFT, padx=10)
        
        ttk.Button(
            action_frame,
            text="📁 Open Location",
            command=self._open_threat_location,
            width=15
        ).pack(side=tk.LEFT, padx=(10, 0))
        
        # Bind tree selection event
        self.threats_tree.bind("<<TreeviewSelect>>", self._on_threat_selected)
    
    def _init_details_tab(self):
        """Initialize details tab"""
        # Details container
        details_container = ttk.Frame(self.details_frame)
        details_container.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Text widget for detailed report
        self.details_text = tk.Text(
            details_container,
            font=("Consolas", 10),
            wrap=tk.WORD,
            bg="#1F2937",
            fg="white",
            relief=tk.FLAT
        )
        
        # Add scrollbar
        text_scroll = ttk.Scrollbar(details_container, command=self.details_text.yview)
        self.details_text.configure(yscrollcommand=text_scroll.set)
        
        # Pack widgets
        self.details_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        text_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Insert placeholder
        self.details_text.insert("1.0", "Detailed scan report will appear here.")
        self.details_text.config(state=tk.DISABLED)
    
    def _init_history_tab(self):
        """Initialize history tab"""
        # History container
        history_container = ttk.Frame(self.history_frame)
        history_container.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Treeview for scan history
        columns = ("Date", "Scan Type", "Threats", "Duration", "Status")
        self.history_tree = ttk.Treeview(
            history_container,
            columns=columns,
            show="headings",
            height=15
        )
        
        # Configure columns
        col_widths = [150, 120, 80, 80, 100]
        for col, width in zip(columns, col_widths):
            self.history_tree.heading(col, text=col, anchor=tk.W)
            self.history_tree.column(col, anchor=tk.W, width=width)
        
        # Add scrollbar
        tree_scroll = ttk.Scrollbar(history_container, orient=tk.VERTICAL, command=self.history_tree.yview)
        self.history_tree.configure(yscrollcommand=tree_scroll.set)
        
        # Pack widgets
        self.history_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Action buttons
        action_frame = ttk.Frame(history_container)
        action_frame.pack(fill=tk.X, pady=(10, 0))
        
        ttk.Button(
            action_frame,
            text="🔄 Refresh",
            command=self._load_scan_history,
            width=12
        ).pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Button(
            action_frame,
            text="📄 View Report",
            command=self._view_selected_report,
            width=12
        ).pack(side=tk.LEFT, padx=10)
        
        ttk.Button(
            action_frame,
            text="🗑️ Delete",
            command=self._delete_selected_report,
            bootstyle="danger",
            width=12
        ).pack(side=tk.LEFT, padx=(10, 0))
        
        # Bind double-click event
        self.history_tree.bind("<Double-1>", self._on_history_double_click)
    
    # ===== EVENT HANDLERS =====
    
    def _on_scan_type_changed(self):
        """Handle scan type change"""
        scan_type = self.scan_type_var.get()
        if scan_type == "custom":
            self.custom_scan_frame.pack(fill=tk.X, pady=(10, 0))
        else:
            self.custom_scan_frame.pack_forget()
    
    def _add_custom_folder(self):
        """Add folder to custom scan list"""
        from tkinter import filedialog
        folder = filedialog.askdirectory(title="Select folder to scan")
        if folder:
            self.custom_paths_listbox.insert(tk.END, folder)
    
    def _add_custom_file(self):
        """Add file to custom scan list"""
        from tkinter import filedialog
        files = filedialog.askopenfilenames(title="Select files to scan")
        for file in files:
            self.custom_paths_listbox.insert(tk.END, file)
    
    def _remove_custom_path(self):
        """Remove selected path from custom scan list"""
        selected = self.custom_paths_listbox.curselection()
        for index in reversed(selected):
            self.custom_paths_listbox.delete(index)
    
    def _start_scan(self):
        """Start the security scan"""
        scan_type = self.scan_type_var.get()
        
        # Validate custom scan
        if scan_type == "custom":
            paths = list(self.custom_paths_listbox.get(0, tk.END))
            if not paths:
                messagebox.showwarning("Custom Scan", "Please add at least one folder or file to scan.")
                return
        
        # Update UI
        self.scan_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self._update_progress("Starting scan...", 0)
        
        # Start scan in background thread
        thread = threading.Thread(target=self._run_scan_thread, daemon=True)
        thread.start()
    
    def _run_scan_thread(self):
        """Run scan in background thread"""
        try:
            scan_type = self.scan_type_var.get()
            scan_paths = None
            
            if scan_type == "custom":
                scan_paths = list(self.custom_paths_listbox.get(0, tk.END))
            
            # Update progress
            self._update_progress("Running scan...", 10)
            
            # Run the scan
            self.current_scan = self.scanner.run_scan(scan_type, scan_paths)
            
            # Update progress
            self._update_progress("Processing results...", 90)
            
            # Update UI with results
            self.frame.after(0, self._display_scan_results, self.current_scan)
            
            # Save to history
            self._add_to_history(self.current_scan)
            
            # Final update
            self._update_progress("Scan completed!", 100)
            
        except Exception as e:
            self.logger.error(f"Scan failed: {e}")
            self.frame.after(0, self._scan_failed, str(e))
        finally:
            self.frame.after(0, self._scan_completed)
    
    def _stop_scan(self):
        """Stop the current scan"""
        if messagebox.askyesno("Stop Scan", "Are you sure you want to stop the scan?"):
            self.scanner.is_scanning = False
            self._update_progress("Scan stopped", 0)
            self._scan_completed()
    
    def _update_progress(self, message: str, value: int):
        """Update progress bar and label"""
        self.frame.after(0, lambda: self.progress_label.config(text=message))
        self.frame.after(0, lambda: self.progress_var.set(value))
    
    def _display_scan_results(self, result: ScanResult):
        """Display scan results in UI"""
        # Update summary tab
        self._update_summary_tab(result)
        
        # Update threats tab
        self._update_threats_tab(result)
        
        # Update details tab
        self._update_details_tab(result)
        
        # Show success message
        if result.threats_found > 0:
            messagebox.showwarning(
                "Scan Complete",
                f"Scan found {result.threats_found} threat(s). Review the Threats tab."
            )
        else:
            messagebox.showinfo(
                "Scan Complete",
                "Scan completed successfully. No threats found."
            )
    
    def _update_summary_tab(self, result: ScanResult):
        """Update summary tab with scan results"""
        # Update stats
        self.stat_widgets['threats'].config(text=str(result.threats_found))
        self.stat_widgets['warnings'].config(text=str(len(result.warnings)))
        self.stat_widgets['duration'].config(text=f"{result.scan_duration:.1f}s")
        
        # Update summary text
        if result.threats_found == 0:
            summary = "✅ No threats detected. Your system appears to be secure."
            color = "#10B981"
        else:
            summary = f"🔴 {result.threats_found} threat(s) detected. Review the Threats tab."
            color = "#EF4444"
        
        self.summary_text.config(text=summary, foreground=color)
        
        # Update recommendations
        self.recommendations_text.config(state=tk.NORMAL)
        self.recommendations_text.delete("1.0", tk.END)
        
        if result.recommendations:
            for rec in result.recommendations:
                self.recommendations_text.insert(tk.END, f"• {rec}\n")
        else:
            self.recommendations_text.insert(tk.END, "No specific recommendations.")
        
        self.recommendations_text.config(state=tk.DISABLED)
    
    def _update_threats_tab(self, result: ScanResult):
        """Update threats tab with detected threats"""
        # Clear existing items
        for item in self.threats_tree.get_children():
            self.threats_tree.delete(item)
        
        # Add threats to treeview
        for i, threat in enumerate(result.threats):
            # Set icon based on severity
            severity = threat['severity'].upper()
            if threat['severity'] == 'critical':
                severity_icon = "🔴"
            elif threat['severity'] == 'high':
                severity_icon = "🟠"
            elif threat['severity'] == 'medium':
                severity_icon = "🟡"
            else:
                severity_icon = "⚪"
            
            self.threats_tree.insert(
                "", tk.END,
                values=(
                    f"{severity_icon} {severity}",
                    threat['name'],
                    threat['type'],
                    threat['path'][:50] + "..." if len(threat['path']) > 50 else threat['path']
                ),
                tags=(threat['severity'],)
            )
        
        # Set tag colors
        self.threats_tree.tag_configure('critical', foreground='#EF4444')
        self.threats_tree.tag_configure('high', foreground='#F97316')
        self.threats_tree.tag_configure('medium', foreground='#F59E0B')
        self.threats_tree.tag_configure('low', foreground='#6B7280')
    
    def _update_details_tab(self, result: ScanResult):
        """Update details tab with full report"""
        self.details_text.config(state=tk.NORMAL)
        self.details_text.delete("1.0", tk.END)
        
        # Generate detailed report
        report = []
        report.append("=" * 70)
        report.append("INDENTURED SERVANT - SECURITY SCAN DETAILED REPORT")
        report.append("=" * 70)
        report.append(f"Scan Type: {result.scan_type}")
        report.append(f"Timestamp: {result.timestamp}")
        report.append(f"Duration: {result.scan_duration:.2f} seconds")
        report.append(f"Threats Found: {result.threats_found}")
        report.append(f"Warnings: {len(result.warnings)}")
        report.append("-" * 70)
        
        # System Info
        report.append("\nSYSTEM INFORMATION:")
        for key, value in result.system_info.items():
            report.append(f"  {key}: {value}")
        
        # Threats
        if result.threats:
            report.append("\n\nDETECTED THREATS:")
            for i, threat in enumerate(result.threats, 1):
                report.append(f"\n{i}. {threat['name']}")
                report.append(f"   Type: {threat['type']}")
                report.append(f"   Severity: {threat['severity']}")
                report.append(f"   Path: {threat['path']}")
                report.append(f"   Description: {threat['description']}")
                report.append(f"   Recommendation: {threat['recommendation']}")
                report.append(f"   Detected: {threat['timestamp']}")
        
        # Warnings
        if result.warnings:
            report.append("\n\nWARNINGS:")
            for warning in result.warnings:
                report.append(f"  • {warning}")
        
        # Recommendations
        if result.recommendations:
            report.append("\n\nRECOMMENDATIONS:")
            for rec in result.recommendations:
                report.append(f"  • {rec}")
        
        report.append("\n" + "=" * 70)
        report.append("END OF REPORT")
        
        # Insert into text widget
        self.details_text.insert("1.0", "\n".join(report))
        self.details_text.config(state=tk.DISABLED)
    
    def _scan_failed(self, error_message: str):
        """Handle scan failure"""
        messagebox.showerror("Scan Failed", f"The scan failed with error:\n\n{error_message}")
        self._update_progress("Scan failed", 0)
    
    def _scan_completed(self):
        """Clean up after scan completion"""
        self.scan_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
    
    # ===== THREAT TAB HANDLERS =====
    
    def _on_threat_selected(self, event):
        """Handle threat selection"""
        selection = self.threats_tree.selection()
        if not selection:
            return
        
        # Get threat data
        item = self.threats_tree.item(selection[0])
        threat_index = self.threats_tree.index(selection[0])
        
        if threat_index < len(self.current_scan.threats):
            threat = self.current_scan.threats[threat_index]
            
            # Display threat details
            detail_text = f"""
Name: {threat['name']}
Type: {threat['type']}
Severity: {threat['severity'].upper()}
Path: {threat['path']}
Detected: {threat['timestamp']}

Description:
{threat['description']}

Recommendation:
{threat['recommendation']}
"""
            self.threat_detail_text.config(state=tk.NORMAL)
            self.threat_detail_text.delete("1.0", tk.END)
            self.threat_detail_text.insert("1.0", detail_text.strip())
            self.threat_detail_text.config(state=tk.DISABLED)
    
    def _remove_threat(self):
        """Remove selected threat"""
        selection = self.threats_tree.selection()
        if not selection:
            messagebox.showinfo("Remove Threat", "Please select a threat to remove.")
            return
        
        if messagebox.askyesno("Remove Threat", "Are you sure you want to remove this threat?\n\nThis will attempt to quarantine or delete the threat."):
            # Placeholder for threat removal logic
            messagebox.showinfo("Threat Removal", "Threat removal feature will be implemented.")
    
    def _copy_threat_details(self):
        """Copy threat details to clipboard"""
        self.threat_detail_text.clipboard_clear()
        self.threat_detail_text.clipboard_append(self.threat_detail_text.get("1.0", tk.END))
        messagebox.showinfo("Copy", "Threat details copied to clipboard.")
    
    def _open_threat_location(self):
        """Open the location of selected threat"""
        selection = self.threats_tree.selection()
        if not selection:
            return
        
        threat_index = self.threats_tree.index(selection[0])
        if threat_index < len(self.current_scan.threats):
            threat = self.current_scan.threats[threat_index]
            import os
            path = threat['path']
            
            if os.path.exists(path):
                if os.path.isfile(path):
                    os.startfile(os.path.dirname(path))
                else:
                    os.startfile(path)
            else:
                messagebox.showwarning("Open Location", f"Path does not exist:\n{path}")
    
    # ===== HISTORY TAB HANDLERS =====
    
    def _load_scan_history(self):
        """Load scan history from reports directory"""
        # Clear existing items
        for item in self.history_tree.get_children():
            self.history_tree.delete(item)
        
        # Load reports
        reports_dir = Path("data/reports")
        if reports_dir.exists():
            for report_file in reports_dir.glob("scan_*.json"):
                try:
                    with open(report_file, 'r') as f:
                        import json
                        report_data = json.load(f)
                    
                    # Extract info for display
                    timestamp = report_data.get('timestamp', 'Unknown')
                    scan_type = report_data.get('scan_type', 'Unknown')
                    threats = report_data.get('threats_found', 0)
                    duration = f"{report_data.get('scan_duration', 0):.1f}s"
                    
                    # Format date
                    try:
                        dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                        date_str = dt.strftime("%Y-%m-%d %H:%M")
                    except:
                        date_str = timestamp
                    
                    # Add to treeview
                    self.history_tree.insert(
                        "", tk.END,
                        values=(date_str, scan_type, threats, duration, "Completed"),
                        tags=(str(report_file),)
                    )
                
                except Exception as e:
                    self.logger.error(f"Failed to load report {report_file}: {e}")
    
    def _add_to_history(self, result: ScanResult):
        """Add current scan to history"""
        # This is called automatically after scan completes
        # Refresh history display
        self._load_scan_history()
    
    def _view_selected_report(self):
        """View selected historical report"""
        selection = self.history_tree.selection()
        if not selection:
            messagebox.showinfo("View Report", "Please select a report to view.")
            return
        
        item = self.history_tree.item(selection[0])
        report_file = item['tags'][0] if item['tags'] else None
        
        if report_file and Path(report_file).exists():
            # Open the report
            import os
            os.startfile(report_file)
        else:
            messagebox.showwarning("View Report", "Could not find the report file.")
    
    def _delete_selected_report(self):
        """Delete selected historical report"""
        selection = self.history_tree.selection()
        if not selection:
            messagebox.showinfo("Delete Report", "Please select a report to delete.")
            return
        
        item = self.history_tree.item(selection[0])
        report_file = item['tags'][0] if item['tags'] else None
        
        if report_file and Path(report_file).exists():
            if messagebox.askyesno("Delete Report", f"Delete report:\n{report_file}?"):
                try:
                    Path(report_file).unlink()
                    
                    # Also delete summary file if exists
                    summary_file = report_file.replace('.json', '_summary.txt')
                    if Path(summary_file).exists():
                        Path(summary_file).unlink()
                    
                    # Refresh history
                    self._load_scan_history()
                    messagebox.showinfo("Delete Report", "Report deleted successfully.")
                
                except Exception as e:
                    messagebox.showerror("Delete Report", f"Failed to delete report:\n{e}")
        else:
            messagebox.showwarning("Delete Report", "Could not find the report file.")
    
    def _on_history_double_click(self, event):
        """Handle double-click on history item"""
        self._view_selected_report()
    
    # ===== QUICK ACTION HANDLERS =====
    
    def _check_updates(self):
        """Check for Windows updates"""
        messagebox.showinfo("Check Updates", "Windows update check will be implemented.")
    
    def _check_firewall(self):
        """Check firewall status"""
        from ..utils.windows_tools import check_firewall_status
        firewall = check_firewall_status()
        
        if firewall:
            status_text = "\n".join([f"{k}: {'✅ Enabled' if v else '❌ Disabled'}" 
                                    for k, v in firewall.items()])
            messagebox.showinfo("Firewall Status", f"Firewall Status:\n\n{status_text}")
        else:
            messagebox.showwarning("Firewall Status", "Could not retrieve firewall status.")
    
    def _check_defender(self):
        """Check Windows Defender status"""
        from ..security_scanner import WindowsSecurityScanner
        scanner = WindowsSecurityScanner()
        status = scanner._check_defender_status()
        
        status_text = []
        status_text.append("Windows Defender Status:")
        status_text.append("-" * 30)
        status_text.append(f"Real-time Protection: {'✅ Enabled' if status['realtime_enabled'] else '❌ Disabled'}")
        status_text.append(f"Tamper Protection: {'✅ Enabled' if status.get('tamper_protection') else '❌ Disabled'}")
        status_text.append(f"Cloud Protection: {'✅ Enabled' if status.get('cloud_enabled') else '❌ Disabled'}")
        status_text.append(f"Definitions Updated: {'✅ Yes' if status['definitions_updated'] else '❌ No'}")
        status_text.append(f"Engine Version: {status.get('engine_version', 'Unknown')}")
        
        messagebox.showinfo("Windows Defender", "\n".join(status_text))
    
    def _view_reports(self):
        """Open reports directory"""
        reports_dir = Path("data/reports")
        if reports_dir.exists():
            import os
            os.startfile(str(reports_dir))
        else:
            messagebox.showinfo("View Reports", "No reports directory found.")
    
    def refresh(self):
        """Refresh the scanner tab"""
        self._load_scan_history()

if __name__ == "__main__":
    # Test the scanner tab
    root = tk.Tk()
    root.geometry("1200x700")
    
    notebook = ttk.Notebook(root)
    notebook.pack(fill=tk.BOTH, expand=True)
    
    scanner_tab = ScannerTab(notebook)
    notebook.add(scanner_tab.frame, text="Security Scanner")
    
    root.mainloop()