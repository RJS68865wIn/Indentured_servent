"""
Dashboard Tab - Shows security overview and quick actions
"""
import tkinter as tk
from tkinter import ttk
import threading
import time
from datetime import datetime
from typing import Dict, Any

from src.utils.windows_tools import get_system_info, check_firewall_status
from src.secure_config import WindowsSecureConfig

class DashboardTab:
    """Dashboard tab showing security overview and metrics"""
    
    def __init__(self, parent):
        self.parent = parent
        self.frame = ttk.Frame(parent)
        
        # Initialize secure config
        self.config = WindowsSecureConfig()
        
        # Create widgets
        self._create_widgets()
        
        # Load initial data
        self.refresh()
    
    def _create_widgets(self):
        """Create dashboard widgets"""
        # Main container with scrollbar
        main_container = ttk.Frame(self.frame)
        main_container.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Canvas for scrolling
        self.canvas = tk.Canvas(main_container, highlightthickness=0)
        scrollbar = ttk.Scrollbar(main_container, orient=tk.VERTICAL, command=self.canvas.yview)
        scrollable_frame = ttk.Frame(self.canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        )
        
        self.canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=scrollbar.set)
        
        # Pack canvas and scrollbar
        self.canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Bind mousewheel for scrolling
        self.canvas.bind_all("<MouseWheel>", self._on_mousewheel)
        
        # ===== WELCOME SECTION =====
        welcome_frame = ttk.LabelFrame(scrollable_frame, text="Welcome", padding=20)
        welcome_frame.pack(fill=tk.X, pady=(0, 20))
        
        welcome_label = ttk.Label(
            welcome_frame,
            text="🔒 Indentured Servant - Cybersecurity Dashboard",
            font=("Segoe UI", 18, "bold")
        )
        welcome_label.pack(anchor=tk.W)
        
        subtitle = ttk.Label(
            welcome_frame,
            text="Your AI-powered security assistant for Windows 11",
            font=("Segoe UI", 11)
        )
        subtitle.pack(anchor=tk.W, pady=(5, 0))
        
        # ===== SECURITY SCORE CARD =====
        score_frame = ttk.LabelFrame(scrollable_frame, text="Security Score", padding=20)
        score_frame.pack(fill=tk.X, pady=(0, 20))
        
        # Score display
        score_container = ttk.Frame(score_frame)
        score_container.pack(fill=tk.X)
        
        # Circular score indicator
        self.score_canvas = tk.Canvas(score_container, width=150, height=150, highlightthickness=0)
        self.score_canvas.pack(side=tk.LEFT, padx=(0, 30))
        
        # Score labels
        score_labels = ttk.Frame(score_container)
        score_labels.pack(side=tk.LEFT, fill=tk.Y, expand=True)
        
        self.score_label = ttk.Label(
            score_labels,
            text="Calculating...",
            font=("Segoe UI", 32, "bold")
        )
        self.score_label.pack(anchor=tk.W)
        
        self.score_text = ttk.Label(
            score_labels,
            text="Overall security score",
            font=("Segoe UI", 12)
        )
        self.score_text.pack(anchor=tk.W, pady=(5, 0))
        
        # Score breakdown
        breakdown_frame = ttk.Frame(score_frame)
        breakdown_frame.pack(fill=tk.X, pady=(20, 0))
        
        self.score_items = {}
        categories = [
            ("🛡️", "Antivirus", "Checking..."),
            ("🔥", "Firewall", "Checking..."),
            ("🔒", "Encryption", "Checking..."),
            ("🔄", "Updates", "Checking..."),
            ("👤", "User Account", "Checking...")
        ]
        
        for icon, name, status in categories:
            item_frame = ttk.Frame(breakdown_frame)
            item_frame.pack(fill=tk.X, pady=5)
            
            icon_label = ttk.Label(item_frame, text=icon, font=("Segoe UI", 14))
            icon_label.pack(side=tk.LEFT, padx=(0, 10))
            
            name_label = ttk.Label(item_frame, text=name, font=("Segoe UI", 10), width=15, anchor=tk.W)
            name_label.pack(side=tk.LEFT)
            
            status_label = ttk.Label(item_frame, text=status, font=("Segoe UI", 10))
            status_label.pack(side=tk.LEFT, padx=(10, 0))
            
            self.score_items[name] = status_label
        
        # ===== QUICK ACTIONS =====
        actions_frame = ttk.LabelFrame(scrollable_frame, text="Quick Actions", padding=20)
        actions_frame.pack(fill=tk.X, pady=(0, 20))
        
        actions_grid = ttk.Frame(actions_frame)
        actions_grid.pack()
        
        actions = [
            ("Run Quick Scan", "🛡️", self._run_quick_scan),
            ("Check Firewall", "🔥", self._check_firewall),
            ("Update System", "🔄", self._check_updates),
            ("Backup Config", "💾", self._backup_config),
            ("VPN Setup", "🔐", self._setup_vpn),
            ("Email Alerts", "📧", self._setup_email)
        ]
        
        for i, (text, icon, command) in enumerate(actions):
            row = i // 3
            col = i % 3
            
            btn = ttk.Button(
                actions_grid,
                text=f"{icon} {text}",
                command=command,
                width=20
            )
            btn.grid(row=row, column=col, padx=10, pady=10, sticky="ew")
    
    def _on_mousewheel(self, event):
        """Handle mousewheel scrolling"""
        self.canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
    
    def _draw_score_gauge(self, score: int):
        """Draw circular score gauge"""
        self.score_canvas.delete("all")
        
        width = 150
        height = 150
        center_x = width / 2
        center_y = height / 2
        radius = 60
        
        # Determine color based on score
        if score >= 80:
            color = "#10B981"  # Green
            text_color = "#10B981"
        elif score >= 60:
            color = "#F59E0B"  # Yellow
            text_color = "#F59E0B"
        else:
            color = "#EF4444"  # Red
            text_color = "#EF4444"
        
        # Draw background circle
        self.score_canvas.create_oval(
            center_x - radius, center_y - radius,
            center_x + radius, center_y + radius,
            outline="#374151", width=10
        )
        
        # Draw score arc
        angle = 360 * (score / 100)
        self.score_canvas.create_arc(
            center_x - radius, center_y - radius,
            center_x + radius, center_y + radius,
            start=90, extent=-angle,
            outline=color, width=10, style=tk.ARC
        )
        
        # Draw score text
        self.score_canvas.create_text(
            center_x, center_y - 10,
            text=f"{score}%",
            fill=text_color,
            font=("Segoe UI", 24, "bold")
        )
        
        self.score_canvas.create_text(
            center_x, center_y + 20,
            text="Score",
            fill="#9CA3AF",
            font=("Segoe UI", 10)
        )
    
    def _calculate_security_score(self) -> int:
        """Calculate overall security score"""
        score = 0
        items = 0
        
        # Check firewall
        firewall_status = check_firewall_status()
        if firewall_status.get('Domain', False):
            score += 20
            self.score_items['Firewall'].config(text="✅ Enabled", foreground="#10B981")
        else:
            self.score_items['Firewall'].config(text="❌ Issues", foreground="#EF4444")
        items += 1
        
        # Check antivirus (Windows Defender)
        try:
            import subprocess
            result = subprocess.run(
                ["powershell", "-Command", "Get-MpComputerStatus"],
                capture_output=True, text=True
            )
            if "AMServiceEnabled : True" in result.stdout:
                score += 20
                self.score_items['Antivirus'].config(text="✅ Active", foreground="#10B981")
            else:
                self.score_items['Antivirus'].config(text="⚠️ Check", foreground="#F59E0B")
        except:
            self.score_items['Antivirus'].config(text="❌ Error", foreground="#EF4444")
        items += 1
        
        # Check BitLocker (encryption)
        try:
            result = subprocess.run(
                ["powershell", "-Command", "Manage-bde -status"],
                capture_output=True, text=True
            )
            if "Protection On" in result.stdout:
                score += 20
                self.score_items['Encryption'].config(text="✅ Enabled", foreground="#10B981")
            else:
                self.score_items['Encryption'].config(text="❌ Off", foreground="#EF4444")
        except:
            self.score_items['Encryption'].config(text="⚠️ Unknown", foreground="#F59E0B")
        items += 1
        
        # Check for updates
        try:
            result = subprocess.run(
                ["powershell", "-Command", "(Get-HotFix | Measure-Object).Count"],
                capture_output=True, text=True
            )
            if int(result.stdout.strip()) > 50:  # Arbitrary threshold
                score += 20
                self.score_items['Updates'].config(text="✅ Updated", foreground="#10B981")
            else:
                self.score_items['Updates'].config(text="⚠️ Old", foreground="#F59E0B")
        except:
            self.score_items['Updates'].config(text="❌ Error", foreground="#EF4444")
        items += 1
        
        # Check user account type
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            if not is_admin:
                score += 20  # Non-admin is safer
                self.score_items['User Account'].config(text="✅ Standard", foreground="#10B981")
            else:
                self.score_items['User Account'].config(text="⚠️ Admin", foreground="#F59E0B")
        except:
            self.score_items['User Account'].config(text="❌ Error", foreground="#EF4444")
        items += 1
        
        # Calculate average
        return score // items if items > 0 else 0
    
    def refresh(self):
        """Refresh dashboard data"""
        # Update in background thread
        def update():
            # Calculate security score
            score = self._calculate_security_score()
            
            # Update UI in main thread
            self.frame.after(0, self._update_ui, score)
        
        thread = threading.Thread(target=update, daemon=True)
        thread.start()
    
    def _update_ui(self, score: int):
        """Update UI elements"""
        # Draw score gauge
        self._draw_score_gauge(score)
        
        # Update score label
        self.score_label.config(text=f"{score}/100")
        
        # Set label color based on score
        if score >= 80:
            color = "#10B981"
            text = "Excellent"
        elif score >= 60:
            color = "#F59E0B"
            text = "Good"
        else:
            color = "#EF4444"
            text = "Needs Attention"
        
        self.score_label.config(foreground=color)
        self.score_text.config(text=f"Overall security score - {text}")
    
    # ===== QUICK ACTION HANDLERS =====
    
    def _run_quick_scan(self):
        """Run quick security scan"""
        from tkinter import messagebox
        messagebox.showinfo("Quick Scan", "Quick scan would run here.")
    
    def _check_firewall(self):
        """Check firewall status"""
        firewall = check_firewall_status()
        status_text = "\n".join([f"{k}: {'✅ Enabled' if v else '❌ Disabled'}" 
                                for k, v in firewall.items()])
        
        from tkinter import messagebox
        messagebox.showinfo("Firewall Status", f"Firewall Status:\n\n{status_text}")
    
    def _check_updates(self):
        """Check for system updates"""
        from tkinter import messagebox
        messagebox.showinfo("Updates", "Update check would run here.")
    
    def _backup_config(self):
        """Backup configuration"""
        from tkinter import messagebox
        messagebox.showinfo("Backup", "Configuration backup would run here.")
    
    def _setup_vpn(self):
        """Setup VPN"""
        from tkinter import messagebox
        messagebox.showinfo("VPN Setup", "VPN setup would run here.")
    
    def _setup_email(self):
        """Setup email alerts"""
        from tkinter import messagebox
        messagebox.showinfo("Email Setup", "Email setup would run here.")

if __name__ == "__main__":
    # Test the dashboard
    root = tk.Tk()
    root.geometry("1000x700")
    
    notebook = ttk.Notebook(root)
    notebook.pack(fill=tk.BOTH, expand=True)
    
    dashboard = DashboardTab(notebook)
    notebook.add(dashboard.frame, text="Dashboard")
    
    root.mainloop()
