"""
Main Window for Indentured Servant GUI
Modern, tabbed interface for cybersecurity operations
"""
import tkinter as tk
from tkinter import ttk, font

from src.gui.dashboard import DashboardTab
from src.gui.scanner_tab import ScannerTab
from src.gui.network_tab import NetworkTab
from src.gui.email_tab import EmailTab
from src.gui.cyber_helper_tab import CyberHelperTab
from src.utils.logger import setup_logger

class MainWindow:
    """Main application window with tabbed interface"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("🔒 Indentured Servant - Cybersecurity Assistant")
        
        # Setup logger
        self.logger = setup_logger()
        
        # Configure modern style
        try:
            self.root.tk.call("source", "azure.tcl")
            self.root.tk.call("set_theme", "dark")
        except:
            # Fallback to default ttk theme
            style = ttk.Style()
            available_themes = style.theme_names()
            if 'vista' in available_themes:
                style.theme_use('vista')
            elif 'clam' in available_themes:
                style.theme_use('clam')
        
        # Configure window
        self.root.geometry("1400x900")
        self.root.minsize(1200, 800)
        
        # Set window icon (if available)
        try:
            self.root.iconbitmap("assets/icon.ico")
        except:
            pass
        
        # Create menu bar
        self._create_menu_bar()
        
        # Create status bar
        self._create_status_bar()
        
        # Create main container
        self.main_container = ttk.Frame(self.root)
        self.main_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        
        # Create notebook (tab container)
        self.notebook = ttk.Notebook(self.main_container)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Initialize tabs
        self.tabs = {}
        self._create_tabs()
        
        # Bind events
        self.root.protocol("WM_DELETE_WINDOW", self._on_closing)
        
        # Center window
        self._center_window()
        
        # Update status
        self._update_status("Ready")
        
        self.logger.info("Main window initialized")
    
    def _create_menu_bar(self):
        """Create the menu bar"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="New Scan", command=self._new_scan, accelerator="Ctrl+N")
        file_menu.add_command(label="Open Report", command=self._open_report, accelerator="Ctrl+O")
        file_menu.add_separator()
        file_menu.add_command(label="Save Report", command=self._save_report, accelerator="Ctrl+S")
        file_menu.add_command(label="Export...", command=self._export_data)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self._on_closing, accelerator="Alt+F4")
        
        # Edit menu
        edit_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Edit", menu=edit_menu)
        edit_menu.add_command(label="Preferences", command=self._open_preferences, accelerator="Ctrl+P")
        edit_menu.add_separator()
        edit_menu.add_command(label="Clear Logs", command=self._clear_logs)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Command Prompt", command=self._open_cmd)
        tools_menu.add_command(label="PowerShell", command=self._open_powershell)
        tools_menu.add_separator()
        tools_menu.add_command(label="Windows Security", command=self._open_windows_security)
        tools_menu.add_command(label="Event Viewer", command=self._open_event_viewer)
        
        # View menu
        view_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="View", menu=view_menu)
        view_menu.add_command(label="Refresh", command=self._refresh_all, accelerator="F5")
        view_menu.add_separator()
        
        # Theme submenu
        theme_menu = tk.Menu(view_menu, tearoff=0)
        view_menu.add_cascade(label="Theme", menu=theme_menu)
        theme_menu.add_command(label="Dark", command=lambda: self._change_theme("dark"))
        theme_menu.add_command(label="Light", command=lambda: self._change_theme("light"))
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="Documentation", command=self._open_docs)
        help_menu.add_command(label="Check for Updates", command=self._check_updates)
        help_menu.add_separator()
        help_menu.add_command(label="About", command=self._show_about)
        
        # Bind keyboard shortcuts
        self.root.bind("<Control-n>", lambda e: self._new_scan())
        self.root.bind("<Control-o>", lambda e: self._open_report())
        self.root.bind("<Control-s>", lambda e: self._save_report())
        self.root.bind("<Control-p>", lambda e: self._open_preferences())
        self.root.bind("<F5>", lambda e: self._refresh_all())
    
    def _create_status_bar(self):
        """Create status bar at bottom of window"""
        self.status_bar = ttk.Frame(self.root, relief=tk.SUNKEN, borderwidth=1)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Status label
        self.status_label = ttk.Label(
            self.status_bar,
            text="Ready",
            anchor=tk.W,
            font=("Segoe UI", 9)
        )
        self.status_label.pack(side=tk.LEFT, padx=10, pady=2)
        
        # Progress bar (hidden by default)
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(
            self.status_bar,
            variable=self.progress_var,
            mode='determinate',
            length=200
        )
        
        # Version label
        self.version_label = ttk.Label(
            self.status_bar,
            text="v1.0.0",
            anchor=tk.E,
            font=("Segoe UI", 9)
        )
        self.version_label.pack(side=tk.RIGHT, padx=10, pady=2)
    
    def _create_tabs(self):
        """Create all application tabs"""
        # Dashboard Tab
        self.tabs['dashboard'] = DashboardTab(self.notebook)
        self.notebook.add(self.tabs['dashboard'].frame, text="📊 Dashboard")
        
        # Security Scanner Tab
        self.tabs['scanner'] = ScannerTab(self.notebook)
        self.notebook.add(self.tabs['scanner'].frame, text="🛡️ Security Scan")
        
        # Network Tools Tab
        self.tabs['network'] = NetworkTab(self.notebook)
        self.notebook.add(self.tabs['network'].frame, text="🌐 Network")
        
        # Email Tools Tab
        self.tabs['email'] = EmailTab(self.notebook)
        self.notebook.add(self.tabs['email'].frame, text="📧 Email")

        # Cyber Helper Tab
        self.tabs['cyber'] = CyberHelperTab(self.notebook)
        self.notebook.add(self.tabs['cyber'].frame, text="🛡️ Cyber Helper")
        
        # Bind tab change event
        self.notebook.bind("<<NotebookTabChanged>>", self._on_tab_changed)
    
    def _on_tab_changed(self, event):
        """Handle tab change events"""
        tab_name = self.notebook.tab(self.notebook.select(), "text")
        self._update_status(f"Switched to {tab_name}")
    
    def _update_status(self, message: str):
        """Update status bar message"""
        self.status_label.config(text=message)
        self.root.update_idletasks()
    
    def show_progress(self, show: bool = True):
        """Show or hide progress bar"""
        if show:
            self.progress_bar.pack(side=tk.RIGHT, padx=10, pady=2)
        else:
            self.progress_bar.pack_forget()
    
    def set_progress(self, value: int):
        """Set progress bar value (0-100)"""
        self.progress_var.set(value)
    
    def _center_window(self):
        """Center window on screen"""
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        
        x = (screen_width // 2) - (width // 2)
        y = (screen_height // 2) - (height // 2)
        
        self.root.geometry(f'{width}x{height}+{x}+{y}')
    
    # ===== MENU COMMANDS =====
    
    def _new_scan(self):
        """Start new security scan"""
        self._update_status("Starting new scan...")
        self.tabs['scanner'].start_quick_scan()
    
    def _open_report(self):
        """Open saved report"""
        from tkinter import filedialog
        file_path = filedialog.askopenfilename(
            title="Open Report",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        if file_path:
            self._update_status(f"Opening report: {file_path}")
    
    def _save_report(self):
        """Save current report"""
        from tkinter import filedialog
        file_path = filedialog.asksaveasfilename(
            title="Save Report",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("Text files", "*.txt"), ("All files", "*.*")]
        )
        if file_path:
            self._update_status(f"Saving report: {file_path}")
    
    def _export_data(self):
        """Export data in various formats"""
        from tkinter import filedialog
        file_path = filedialog.asksaveasfilename(
            title="Export Data",
            defaultextension=".csv",
            filetypes=[
                ("CSV files", "*.csv"),
                ("JSON files", "*.json"),
                ("PDF files", "*.pdf"),
                ("All files", "*.*")
            ]
        )
        if file_path:
            self._update_status(f"Exporting data to: {file_path}")
    
    def _open_preferences(self):
        """Open preferences/settings window"""
        # Simple preferences dialog for a few key settings (reset remembered consent)
        dlg = tk.Toplevel(self.root)
        dlg.title('Preferences')
        dlg.transient(self.root)
        dlg.grab_set()

        frm = ttk.Frame(dlg, padding=12)
        frm.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frm, text='Scan & Privacy Settings', font=('Segoe UI', 10, 'bold')).pack(anchor=tk.W)

        # Access cyber helper config if available
        helper = self.tabs.get('cyber').helper if 'cyber' in self.tabs else None
        current = False
        if helper:
            current = bool(helper.config.get('vuln_scan', {}).get('allow_public_targets', False))

        var = tk.BooleanVar(value=current)
        chk = ttk.Checkbutton(frm, text='Allow public targets (persisted)', variable=var)
        chk.pack(anchor=tk.W, pady=(6, 6))

        def do_save():
            if not helper:
                self._show_message('Preferences', 'Cyber helper not available in this session.')
                return
            helper.config.setdefault('vuln_scan', {})['allow_public_targets'] = bool(var.get())
            ok = helper.save_config()
            self._show_message('Preferences', f'Settings saved (ok={ok}).')

        def do_reset():
            if not helper:
                self._show_message('Preferences', 'Cyber helper not available in this session.')
                return
            ok = helper.reset_allow_public_targets()
            var.set(False)
            self._show_message('Preferences', f'Reset remembered choices (ok={ok}).')

        btns = ttk.Frame(frm)
        btns.pack(anchor=tk.E, pady=(12, 0))
        ttk.Button(btns, text='Save', command=do_save).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(btns, text='Reset remembered choices', command=do_reset).pack(side=tk.LEFT)

        ttk.Button(frm, text='Close', command=dlg.destroy).pack(anchor=tk.E, pady=(12, 0))

    
    def _clear_logs(self):
        """Clear application logs"""
        if tk.messagebox.askyesno("Clear Logs", "Are you sure you want to clear all logs?"):
            import shutil
            try:
                shutil.rmtree("data/logs", ignore_errors=True)
                import os
                os.makedirs("data/logs", exist_ok=True)
                self._update_status("Logs cleared")
                self._show_message("Success", "Logs have been cleared.")
            except Exception as e:
                self._show_message("Error", f"Failed to clear logs: {e}")
    
    def _open_cmd(self):
        """Open Command Prompt"""
        import subprocess
        try:
            subprocess.Popen(["cmd.exe"])
            self._update_status("Command Prompt opened")
        except Exception as e:
            self._show_message("Error", f"Failed to open Command Prompt: {e}")
    
    def _open_powershell(self):
        """Open PowerShell"""
        import subprocess
        try:
            subprocess.Popen(["powershell.exe"])
            self._update_status("PowerShell opened")
        except Exception as e:
            self._show_message("Error", f"Failed to open PowerShell: {e}")
    
    def _open_windows_security(self):
        """Open Windows Security Center"""
        import subprocess
        try:
            subprocess.Popen(["windowsdefender:"], shell=True)
            self._update_status("Windows Security opened")
        except Exception as e:
            self._show_message("Error", f"Failed to open Windows Security: {e}")
    
    def _open_event_viewer(self):
        """Open Windows Event Viewer"""
        import subprocess
        try:
            subprocess.Popen(["eventvwr.exe"])
            self._update_status("Event Viewer opened")
        except Exception as e:
            self._show_message("Error", f"Failed to open Event Viewer: {e}")
    
    def _refresh_all(self):
        """Refresh all tabs"""
        self._update_status("Refreshing...")
        for tab in self.tabs.values():
            tab.refresh()
        self._update_status("Refreshed")
    
    def _change_theme(self, theme_name: str):
        """Change application theme"""
        try:
            self.style.theme_use(theme_name)
            self._update_status(f"Theme changed to {theme_name}")
        except tk.TclError:
            self._update_status(f"Theme {theme_name} not available")
    
    def _open_docs(self):
        """Open documentation"""
        import webbrowser
        webbrowser.open("https://github.com/yourusername/indentured-servant")
    
    def _check_updates(self):
        """Check for updates"""
        self._show_message("Check Updates", "Update check would run here.")
    
    def _show_about(self):
        """Show about dialog"""
        about_text = """Indentured Servant - Cybersecurity Assistant
Version 1.0.0

A comprehensive cybersecurity tool for Windows 11
with AI-powered security analysis and automation.

Features:
• Security scanning and monitoring
• Network analysis and VPN setup
• Email security and alerts
• AI-powered threat detection

© 2025 All rights reserved.
"""
        tk.messagebox.showinfo("About Indentured Servant", about_text)
    
    def _show_message(self, title: str, message: str):
        """Show message dialog"""
        tk.messagebox.showinfo(title, message)
    
    def _on_closing(self):
        """Handle window closing"""
        if tk.messagebox.askyesno("Quit", "Are you sure you want to quit?"):
            self.logger.info("Application closing")
            self.root.destroy()

if __name__ == "__main__":
    # Test the main window
    root = tk.Tk()
    app = MainWindow(root)
    root.mainloop()