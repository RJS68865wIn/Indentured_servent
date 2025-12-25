"""
Network Tools Tab - GUI for network scanning and VPN management
"""
import tkinter as tk
from tkinter import ttk, messagebox
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any

from ..network_tools import NetworkTools, NetworkDevice
from ..utils.logger import setup_logger
from ..utils.windows_tools import get_local_ip

class NetworkTab:
    """Network Tools tab for scanning and VPN management"""
    
    def __init__(self, parent):
        self.parent = parent
        self.frame = ttk.Frame(parent)
        
        # Initialize network tools and logger
        self.tools = NetworkTools()
        self.logger = setup_logger("NetworkGUI")
        
        # State variables
        self.is_scanning = False
        self.current_devices = []
        
        # Create widgets
        self._create_widgets()
        
        # Load initial data
        self._update_network_info()
    
    def _create_widgets(self):
        """Create network tab widgets"""
        # Main container with notebook
        self.notebook = ttk.Notebook(self.frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create tabs
        self.vpn_frame = self._create_vpn_tab()
        self.scan_frame = self._create_scan_tab()
        self.analysis_frame = self._create_analysis_tab()
        self.tools_frame = self._create_tools_tab()
        
        self.notebook.add(self.vpn_frame, text="🔐 VPN")
        self.notebook.add(self.scan_frame, text="🔍 Network Scan")
        self.notebook.add(self.analysis_frame, text="📊 Analysis")
        self.notebook.add(self.tools_frame, text="🛠️ Tools")
    
    def _create_vpn_tab(self) -> ttk.Frame:
        """Create VPN management tab"""
        frame = ttk.Frame(self.notebook)
        
        # VPN setup section
        setup_frame = ttk.LabelFrame(frame, text="WireGuard VPN Setup", padding=20)
        setup_frame.pack(fill=tk.X, padx=20, pady=20)
        
        # Device name input
        name_frame = ttk.Frame(setup_frame)
        name_frame.pack(fill=tk.X, pady=(0, 15))
        
        ttk.Label(name_frame, text="Device Name:", width=15).pack(side=tk.LEFT)
        self.device_name_var = tk.StringVar(value="MyPhone")
        name_entry = ttk.Entry(name_frame, textvariable=self.device_name_var, width=30)
        name_entry.pack(side=tk.LEFT, padx=(10, 0))
        
        # Port input
        port_frame = ttk.Frame(setup_frame)
        port_frame.pack(fill=tk.X, pady=(0, 20))
        
        ttk.Label(port_frame, text="VPN Port:", width=15).pack(side=tk.LEFT)
        self.vpn_port_var = tk.StringVar(value="51820")
        port_entry = ttk.Entry(port_frame, textvariable=self.vpn_port_var, width=10)
        port_entry.pack(side=tk.LEFT, padx=(10, 0))
        ttk.Label(port_frame, text="(UDP)").pack(side=tk.LEFT, padx=(5, 0))
        
        # Setup button
        ttk.Button(
            setup_frame,
            text="🚀 Setup WireGuard VPN",
            command=self._setup_vpn,
            bootstyle="success",
            width=25
        ).pack(pady=(0, 10))
        
        # Status display
        self.vpn_status_text = tk.Text(
            setup_frame,
            height=8,
            font=("Consolas", 9),
            wrap=tk.WORD,
            bg="#1F2937",
            fg="white",
            relief=tk.FLAT
        )
        self.vpn_status_text.pack(fill=tk.X, pady=(10, 0))
        self.vpn_status_text.insert("1.0", "VPN status will appear here.")
        self.vpn_status_text.config(state=tk.DISABLED)
        
        # VPN control section
        control_frame = ttk.LabelFrame(frame, text="VPN Controls", padding=20)
        control_frame.pack(fill=tk.X, padx=20, pady=(0, 20))
        
        # Status indicator
        status_container = ttk.Frame(control_frame)
        status_container.pack(fill=tk.X, pady=(0, 15))
        
        self.vpn_status_label = ttk.Label(
            status_container,
            text="Status: Checking...",
            font=("Segoe UI", 11)
        )
        self.vpn_status_label.pack(side=tk.LEFT)
        
        self.vpn_status_indicator = tk.Canvas(
            status_container,
            width=20,
            height=20,
            highlightthickness=0
        )
        self.vpn_status_indicator.pack(side=tk.RIGHT)
        
        # Control buttons
        button_frame = ttk.Frame(control_frame)
        button_frame.pack(fill=tk.X)
        
        self.start_vpn_btn = ttk.Button(
            button_frame,
            text="▶️ Start VPN",
            command=self._start_vpn,
            bootstyle="success",
            width=15
        )
        self.start_vpn_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        self.stop_vpn_btn = ttk.Button(
            button_frame,
            text="⏹️ Stop VPN",
            command=self._stop_vpn,
            bootstyle="danger",
            width=15
        )
        self.stop_vpn_btn.pack(side=tk.LEFT, padx=10)
        
        ttk.Button(
            button_frame,
            text="🔄 Refresh Status",
            command=self._refresh_vpn_status,
            width=15
        ).pack(side=tk.LEFT, padx=(10, 0))
        
        # Instructions section
        inst_frame = ttk.LabelFrame(frame, text="Setup Instructions", padding=15)
        inst_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 20))
        
        self.instructions_text = tk.Text(
            inst_frame,
            font=("Segoe UI", 10),
            wrap=tk.WORD,
            bg="#1F2937",
            fg="white",
            relief=tk.FLAT
        )
        self.instructions_text.pack(fill=tk.BOTH, expand=True)
        
        instructions = """
        1. Click "Setup WireGuard VPN" to generate config files
        2. Port forward the VPN port (51820/UDP) in your router
        3. Install WireGuard on your mobile device
        4. Scan the QR code or import the config file
        5. Start the VPN server on this computer
        6. Connect from your mobile device
        
        Note: You may need to configure Windows Firewall to allow the VPN port.
        """
        
        self.instructions_text.insert("1.0", instructions)
        self.instructions_text.config(state=tk.DISABLED)
        
        # Initial status check
        self._refresh_vpn_status()
        
        return frame
    
    def _create_scan_tab(self) -> ttk.Frame:
        """Create network scan tab"""
        frame = ttk.Frame(self.notebook)
        
        # Scan controls
        control_frame = ttk.LabelFrame(frame, text="Network Scanner", padding=20)
        control_frame.pack(fill=tk.X, padx=20, pady=20)
        
        # Network info display
        info_frame = ttk.Frame(control_frame)
        info_frame.pack(fill=tk.X, pady=(0, 15))
        
        self.network_info_label = ttk.Label(
            info_frame,
            text="Local Network: Scanning...",
            font=("Segoe UI", 10)
        )
        self.network_info_label.pack(anchor=tk.W)
        
        # Scan button
        self.scan_button = ttk.Button(
            control_frame,
            text="🔍 Scan Network",
            command=self._scan_network,
            bootstyle="primary",
            width=20
        )
        self.scan_button.pack(pady=(0, 10))
        
        # Progress bar
        self.scan_progress_var = tk.DoubleVar()
        self.scan_progress = ttk.Progressbar(
            control_frame,
            variable=self.scan_progress_var,
            mode='determinate',
            length=400
        )
        self.scan_progress.pack(fill=tk.X, pady=(0, 10))
        
        self.scan_status_label = ttk.Label(
            control_frame,
            text="Ready to scan",
            font=("Segoe UI", 9)
        )
        self.scan_status_label.pack(anchor=tk.W)
        
        # Results display
        results_frame = ttk.LabelFrame(frame, text="Discovered Devices", padding=15)
        results_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 20))
        
        # Create treeview for devices
        columns = ("IP", "Hostname", "MAC", "Vendor", "Open Ports", "OS")
        self.devices_tree = ttk.Treeview(
            results_frame,
            columns=columns,
            show="headings",
            height=15
        )
        
        # Configure columns
        col_widths = [120, 150, 140, 120, 100, 100]
        for col, width in zip(columns, col_widths):
            self.devices_tree.heading(col, text=col, anchor=tk.W)
            self.devices_tree.column(col, anchor=tk.W, width=width)
        
        # Add scrollbar
        tree_scroll = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.devices_tree.yview)
        self.devices_tree.configure(yscrollcommand=tree_scroll.set)
        
        # Pack widgets
        self.devices_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Device details panel
        detail_frame = ttk.LabelFrame(frame, text="Device Details", padding=15)
        detail_frame.pack(fill=tk.X, padx=20, pady=(0, 20))
        
        self.device_detail_text = tk.Text(
            detail_frame,
            height=6,
            font=("Consolas", 9),
            wrap=tk.WORD,
            bg="#1F2937",
            fg="white",
            relief=tk.FLAT
        )
        self.device_detail_text.pack(fill=tk.X)
        self.device_detail_text.insert("1.0", "Select a device to view details.")
        self.device_detail_text.config(state=tk.DISABLED)
        
        # Action buttons
        action_frame = ttk.Frame(detail_frame)
        action_frame.pack(fill=tk.X, pady=(10, 0))
        
        ttk.Button(
            action_frame,
            text="🔍 Port Scan",
            command=self._port_scan_selected,
            width=12
        ).pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Button(
            action_frame,
            text="📋 Copy Info",
            command=self._copy_device_info,
            width=12
        ).pack(side=tk.LEFT, padx=10)
        
        ttk.Button(
            action_frame,
            text="🔄 Refresh",
            command=self._refresh_devices,
            width=12
        ).pack(side=tk.LEFT, padx=(10, 0))
        
        # Bind tree selection
        self.devices_tree.bind("<<TreeviewSelect>>", self._on_device_selected)
        
        return frame
    
    def _create_analysis_tab(self) -> ttk.Frame:
        """Create network analysis tab"""
        frame = ttk.Frame(self.notebook)
        
        # Port scanner section
        port_frame = ttk.LabelFrame(frame, text="Port Scanner", padding=20)
        port_frame.pack(fill=tk.X, padx=20, pady=20)
        
        # Target input
        target_frame = ttk.Frame(port_frame)
        target_frame.pack(fill=tk.X, pady=(0, 15))
        
        ttk.Label(target_frame, text="Target IP:", width=10).pack(side=tk.LEFT)
        self.target_ip_var = tk.StringVar(value="127.0.0.1")
        target_entry = ttk.Entry(target_frame, textvariable=self.target_ip_var, width=20)
        target_entry.pack(side=tk.LEFT, padx=(10, 0))
        
        # Port range
        range_frame = ttk.Frame(port_frame)
        range_frame.pack(fill=tk.X, pady=(0, 15))
        
        ttk.Label(range_frame, text="Ports:", width=10).pack(side=tk.LEFT)
        
        # Quick scan buttons
        quick_frame = ttk.Frame(range_frame)
        quick_frame.pack(side=tk.LEFT, padx=(10, 0))
        
        quick_scans = [
            ("Common", "1-1024"),
            ("Web", "80,443,8080,8443"),
            ("Services", "21,22,23,25,53,110,143,443,3389"),
            ("All", "1-65535")
        ]
        
        for text, ports in quick_scans:
            btn = ttk.Button(
                quick_frame,
                text=text,
                command=lambda p=ports: self._set_port_range(p),
                width=8
            )
            btn.pack(side=tk.LEFT, padx=(0, 5))
        
        # Custom port input
        custom_frame = ttk.Frame(port_frame)
        custom_frame.pack(fill=tk.X, pady=(0, 15))
        
        ttk.Label(custom_frame, text="Custom:", width=10).pack(side=tk.LEFT)
        self.custom_ports_var = tk.StringVar(value="80,443,3389")
        custom_entry = ttk.Entry(custom_frame, textvariable=self.custom_ports_var, width=30)
        custom_entry.pack(side=tk.LEFT, padx=(10, 0))
        
        # Scan button
        ttk.Button(
            port_frame,
            text="🚀 Start Port Scan",
            command=self._start_port_scan,
            bootstyle="success",
            width=20
        ).pack(pady=(0, 10))
        
        # Port scan results
        results_frame = ttk.LabelFrame(port_frame, text="Scan Results", padding=15)
        results_frame.pack(fill=tk.X, pady=(10, 0))
        
        # Treeview for port results
        columns = ("Port", "Service", "Status", "Description")
        self.ports_tree = ttk.Treeview(
            results_frame,
            columns=columns,
            show="headings",
            height=8
        )
        
        # Configure columns
        col_widths = [80, 100, 80, 200]
        for col, width in zip(columns, col_widths):
            self.ports_tree.heading(col, text=col, anchor=tk.W)
            self.ports_tree.column(col, anchor=tk.W, width=width)
        
        # Add scrollbar
        tree_scroll = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.ports_tree.yview)
        self.ports_tree.configure(yscrollcommand=tree_scroll.set)
        
        # Pack widgets
        self.ports_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Connection analysis section
        conn_frame = ttk.LabelFrame(frame, text="Active Connections", padding=20)
        conn_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 20))
        
        # Refresh button
        ttk.Button(
            conn_frame,
            text="🔄 Refresh Connections",
            command=self._refresh_connections,
            width=20
        ).pack(anchor=tk.W, pady=(0, 10))
        
        # Treeview for connections
        conn_columns = ("Local", "Remote", "Process", "State")
        self.conn_tree = ttk.Treeview(
            conn_frame,
            columns=conn_columns,
            show="headings",
            height=10
        )
        
        # Configure columns
        conn_widths = [150, 150, 100, 80]
        for col, width in zip(conn_columns, conn_widths):
            self.conn_tree.heading(col, text=col, anchor=tk.W)
            self.conn_tree.column(col, anchor=tk.W, width=width)
        
        # Add scrollbar
        conn_scroll = ttk.Scrollbar(conn_frame, orient=tk.VERTICAL, command=self.conn_tree.yview)
        self.conn_tree.configure(yscrollcommand=conn_scroll.set)
        
        # Pack widgets
        self.conn_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        conn_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        return frame
    
    def _create_tools_tab(self) -> ttk.Frame:
        """Create network tools tab"""
        frame = ttk.Frame(self.notebook)
        
        # Network utilities
        utils_frame = ttk.LabelFrame(frame, text="Network Utilities", padding=20)
        utils_frame.pack(fill=tk.X, padx=20, pady=20)
        
        # Network info display
        info_text = tk.Text(
            utils_frame,
            height=10,
            font=("Consolas", 9),
            wrap=tk.WORD,
            bg="#1F2937",
            fg="white",
            relief=tk.FLAT
        )
        info_text.pack(fill=tk.X, pady=(0, 15))
        self.network_info_text = info_text
        
        # Refresh info button
        ttk.Button(
            utils_frame,
            text="🔄 Refresh Network Info",
            command=self._update_network_info,
            width=20
        ).pack(pady=(0, 10))
        
        # Tool buttons grid
        tools_grid = ttk.Frame(utils_frame)
        tools_grid.pack(fill=tk.X, pady=10)
        
        tools = [
            ("🗑️ Flush DNS", self._flush_dns, "Clear DNS cache"),
            ("🔁 Reset Network", self._reset_network, "Reset network adapters"),
            ("📊 Connection Stats", self._show_stats, "Show network statistics"),
            ("🔒 Firewall Check", self._check_firewall, "Check firewall status"),
        ]
        
        for i, (text, command, tooltip) in enumerate(tools):
            row = i // 2
            col = i % 2
            
            btn = ttk.Button(
                tools_grid,
                text=text,
                command=command,
                width=20,
                bootstyle="outline"
            )
            btn.grid(row=row, column=col, padx=10, pady=10, sticky="ew")
        
        # Configure grid columns
        tools_grid.grid_columnconfigure(0, weight=1)
        tools_grid.grid_columnconfigure(1, weight=1)
        
        # Log section
        log_frame = ttk.LabelFrame(frame, text="Network Log", padding=15)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 20))
        
        self.network_log_text = tk.Text(
            log_frame,
            font=("Consolas", 9),
            wrap=tk.WORD,
            bg="#1F2937",
            fg="white",
            relief=tk.FLAT
        )
        
        # Add scrollbar
        log_scroll = ttk.Scrollbar(log_frame, command=self.network_log_text.yview)
        self.network_log_text.configure(yscrollcommand=log_scroll.set)
        
        # Pack widgets
        self.network_log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        log_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Initial log message
        self._log("Network tools initialized.")
        
        return frame
    
    # ===== VPN METHODS =====
    
    def _setup_vpn(self):
        """Setup WireGuard VPN"""
        device_name = self.device_name_var.get().strip()
        port_str = self.vpn_port_var.get().strip()
        
        if not device_name:
            messagebox.showwarning("Setup VPN", "Please enter a device name.")
            return
        
        try:
            port = int(port_str)
            if port < 1 or port > 65535:
                raise ValueError("Port out of range")
        except ValueError:
            messagebox.showwarning("Setup VPN", "Please enter a valid port number (1-65535).")
            return
        
        # Disable button during setup
        self._update_vpn_status("Setting up VPN...", "yellow")
        
        # Run setup in background thread
        thread = threading.Thread(target=self._setup_vpn_thread, args=(device_name, port), daemon=True)
        thread.start()
    
    def _setup_vpn_thread(self, device_name: str, port: int):
        """VPN setup in background thread"""
        try:
            result = self.tools.setup_wireguard_vpn(device_name, port)
            
            if result['success']:
                # Update status display
                status_text = f"""
✅ VPN Setup Complete!

Server Config: {result['server_config']}
Client Config: {result['client_config']}
Public IP: {result['public_ip']}
VPN Port: {result['port']}

{result['setup_instructions']}
                """
                
                self.frame.after(0, self._update_vpn_display, status_text, "green")
                self.frame.after(0, self._update_vpn_status, "VPN Ready", "green")
                
                # Show QR code if generated
                if result.get('qr_code'):
                    self.frame.after(0, lambda: messagebox.showinfo(
                        "VPN Setup Complete",
                        f"QR code generated: {result['qr_code']}\n\nScan with WireGuard app on mobile device."
                    ))
            else:
                self.frame.after(0, lambda: self._update_vpn_status(f"Setup Failed: {result.get('error', 'Unknown error')}", "red"))
                
        except Exception as e:
            self.frame.after(0, lambda: self._update_vpn_status(f"Error: {str(e)}", "red"))
    
    def _start_vpn(self):
        """Start WireGuard VPN"""
        self._update_vpn_status("Starting VPN...", "yellow")
        
        thread = threading.Thread(target=self._start_vpn_thread, daemon=True)
        thread.start()
    
    def _start_vpn_thread(self):
        """Start VPN in background thread"""
        try:
            result = self.tools.start_wireguard_vpn()
            
            if result['success']:
                self.frame.after(0, lambda: self._update_vpn_status("VPN Running", "green"))
                self.frame.after(0, lambda: self._show_vpn_result(result))
            else:
                self.frame.after(0, lambda: self._update_vpn_status(f"Failed: {result.get('error', 'Unknown error')}", "red"))
                
        except Exception as e:
            self.frame.after(0, lambda: self._update_vpn_status(f"Error: {str(e)}", "red"))
    
    def _stop_vpn(self):
        """Stop WireGuard VPN"""
        if messagebox.askyesno("Stop VPN", "Are you sure you want to stop the VPN?"):
            self._update_vpn_status("Stopping VPN...", "yellow")
            
            thread = threading.Thread(target=self._stop_vpn_thread, daemon=True)
            thread.start()
    
    def _stop_vpn_thread(self):
        """Stop VPN in background thread"""
        try:
            result = self.tools.stop_wireguard_vpn()
            
            if result['success']:
                self.frame.after(0, lambda: self._update_vpn_status("VPN Stopped", "red"))
                self.frame.after(0, lambda: self._show_vpn_result(result))
            else:
                self.frame.after(0, lambda: self._update_vpn_status(f"Failed: {result.get('error', 'Unknown error')}", "red"))
                
        except Exception as e:
            self.frame.after(0, lambda: self._update_vpn_status(f"Error: {str(e)}", "red"))
    
    def _refresh_vpn_status(self):
        """Refresh VPN status"""
        self._update_vpn_status("Checking...", "yellow")
        
        thread = threading.Thread(target=self._refresh_vpn_status_thread, daemon=True)
        thread.start()
    
    def _refresh_vpn_status_thread(self):
        """Refresh VPN status in background"""
        try:
            status = self.tools.get_vpn_status()
            
            if status.get('installed'):
                if status.get('running'):
                    self.frame.after(0, lambda: self._update_vpn_status("VPN Running", "green"))
                else:
                    self.frame.after(0, lambda: self._update_vpn_status("VPN Stopped", "red"))
            else:
                self.frame.after(0, lambda: self._update_vpn_status("WireGuard Not Installed", "orange"))
                
        except Exception as e:
            self.frame.after(0, lambda: self._update_vpn_status(f"Error: {str(e)}", "red"))
    
    def _update_vpn_status(self, message: str, color: str):
        """Update VPN status display"""
        self.vpn_status_label.config(text=f"Status: {message}")
        
        # Update indicator
        self.vpn_status_indicator.delete("all")
        
        color_map = {
            "green": "#10B981",
            "yellow": "#F59E0B",
            "red": "#EF4444",
            "orange": "#F97316"
        }
        
        fill_color = color_map.get(color, "#6B7280")
        self.vpn_status_indicator.create_oval(2, 2, 18, 18, fill=fill_color, outline="")
    
    def _update_vpn_display(self, text: str, color: str = "white"):
        """Update VPN status text display"""
        self.vpn_status_text.config(state=tk.NORMAL)
        self.vpn_status_text.delete("1.0", tk.END)
        self.vpn_status_text.insert("1.0", text)
        self.vpn_status_text.config(state=tk.DISABLED)
    
    def _show_vpn_result(self, result: Dict[str, Any]):
        """Show VPN operation result"""
        messagebox.showinfo("VPN Operation", result.get('message', 'Operation completed.'))
    
    # ===== NETWORK SCAN METHODS =====
    
    def _scan_network(self):
        """Scan local network"""
        if self.is_scanning:
            messagebox.showinfo("Scan", "Scan already in progress.")
            return
        
        self.is_scanning = True
        self.scan_button.config(state=tk.DISABLED)
        self._update_scan_status("Scanning network...", 0)
        
        thread = threading.Thread(target=self._scan_network_thread, daemon=True)
        thread.start()
    
    def _scan_network_thread(self):
        """Network scan in background thread"""
        try:
            # Update progress
            self.frame.after(0, lambda: self._update_scan_status("Discovering devices...", 30))
            
            # Scan network
            devices = self.tools.scan_local_network(timeout=1.0)
            self.current_devices = devices
            
            # Update progress
            self.frame.after(0, lambda: self._update_scan_status("Processing results...", 80))
            
            # Update UI
            self.frame.after(0, self._update_devices_display, devices)
            self.frame.after(0, lambda: self._update_scan_status(f"Found {len(devices)} devices", 100))
            
        except Exception as e:
            self.frame.after(0, lambda: self._update_scan_status(f"Scan failed: {str(e)}", 0))
            self._log(f"Network scan failed: {e}")
        finally:
            self.frame.after(0, lambda: self.scan_button.config(state=tk.NORMAL))
            self.frame.after(0, lambda: setattr(self, 'is_scanning', False))
    
    def _update_scan_status(self, message: str, progress: int):
        """Update scan status display"""
        self.scan_status_label.config(text=message)
        self.scan_progress_var.set(progress)
    
    def _update_devices_display(self, devices: List[NetworkDevice]):
        """Update devices treeview"""
        # Clear existing items
        for item in self.devices_tree.get_children():
            self.devices_tree.delete(item)
        
        # Add devices to treeview
        for device in devices:
            open_ports_str = ', '.join(map(str, device.open_ports[:3]))
            if len(device.open_ports) > 3:
                open_ports_str += '...'
            
            self.devices_tree.insert(
                "", tk.END,
                values=(
                    device.ip,
                    device.hostname,
                    device.mac,
                    device.vendor,
                    open_ports_str,
                    device.os_guess
                )
            )
    
    def _on_device_selected(self, event):
        """Handle device selection"""
        selection = self.devices_tree.selection()
        if not selection or not self.current_devices:
            return
        
        # Get selected device
        item = self.devices_tree.item(selection[0])
        ip = item['values'][0]
        
        # Find device in current devices
        device = None
        for d in self.current_devices:
            if d.ip == ip:
                device = d
                break
        
        if device:
            # Display device details
            details = f"""
IP Address: {device.ip}
Hostname: {device.hostname}
MAC Address: {device.mac}
Vendor: {device.vendor}
OS Guess: {device.os_guess}
Last Seen: {device.last_seen}

Open Ports: {', '.join(map(str, device.open_ports)) if device.open_ports else 'None'}
            """
            
            self.device_detail_text.config(state=tk.NORMAL)
            self.device_detail_text.delete("1.0", tk.END)
            self.device_detail_text.insert("1.0", details.strip())
            self.device_detail_text.config(state=tk.DISABLED)
    
    def _port_scan_selected(self):
        """Port scan selected device"""
        selection = self.devices_tree.selection()
        if not selection:
            messagebox.showinfo("Port Scan", "Please select a device first.")
            return
        
        item = self.devices_tree.item(selection[0])
        ip = item['values'][0]
        
        self.target_ip_var.set(ip)
        self.notebook.select(self.analysis_frame)
    
    def _copy_device_info(self):
        """Copy device info to clipboard"""
        selection = self.devices_tree.selection()
        if not selection:
            return
        
        item = self.devices_tree.item(selection[0])
        info = '\t'.join(map(str, item['values']))
        
        self.device_detail_text.clipboard_clear()
        self.device_detail_text.clipboard_append(info)
        messagebox.showinfo("Copy", "Device info copied to clipboard.")
    
    def _refresh_devices(self):
        """Refresh devices display"""
        if self.current_devices:
            self._update_devices_display(self.current_devices)
    
    # ===== PORT SCAN METHODS =====
    
    def _set_port_range(self, ports: str):
        """Set port range for scanning"""
        self.custom_ports_var.set(ports)
    
    def _start_port_scan(self):
        """Start port scan"""
        target_ip = self.target_ip_var.get().strip()
        ports_str = self.custom_ports_var.get().strip()
        
        if not target_ip:
            messagebox.showwarning("Port Scan", "Please enter a target IP.")
            return
        
        # Parse ports
        ports = []
        try:
            for part in ports_str.split(','):
                part = part.strip()
                if '-' in part:
                    start, end = map(int, part.split('-'))
                    ports.extend(range(start, end + 1))
                else:
                    ports.append(int(part))
        except ValueError:
            messagebox.showwarning("Port Scan", "Invalid port specification.")
            return
        
        # Clear previous results
        for item in self.ports_tree.get_children():
            self.ports_tree.delete(item)
        
        # Start scan in background
        thread = threading.Thread(
            target=self._port_scan_thread,
            args=(target_ip, ports),
            daemon=True
        )
        thread.start()
    
    def _port_scan_thread(self, target_ip: str, ports: List[int]):
        """Port scan in background thread"""
        try:
            self._log(f"Starting port scan on {target_ip}")
            
            result = self.tools.port_scan(target_ip, ports)
            
            # Update UI with results
            self.frame.after(0, self._update_port_results, result)
            
            self._log(f"Port scan completed: {len(result['open_ports'])} open ports")
            
        except Exception as e:
            self.frame.after(0, lambda: messagebox.showerror("Port Scan", f"Scan failed: {e}"))
            self._log(f"Port scan failed: {e}")
    
    def _update_port_results(self, result: Dict[str, Any]):
        """Update port scan results display"""
        for port_info in result['open_ports']:
            self.ports_tree.insert(
                "", tk.END,
                values=(
                    port_info['port'],
                    port_info['service'],
                    port_info['status'],
                    f"Open - {port_info['service']} service"
                )
            )
        
        # Show summary
        messagebox.showinfo(
            "Port Scan Complete",
            f"Scanned {result['ports_scanned']} ports on {result['target']}\n"
            f"Found {len(result['open_ports'])} open ports\n"
            f"Duration: {result['scan_duration']:.2f} seconds"
        )
    
    # ===== CONNECTION METHODS =====
    
    def _refresh_connections(self):
        """Refresh active connections"""
        # Clear existing items
        for item in self.conn_tree.get_children():
            self.conn_tree.delete(item)
        
        try:
            connections = self.tools.check_open_connections()
            
            for conn in connections:
                local = f"{conn['local_address']}:{conn['local_port']}"
                remote = f"{conn['remote_address']}:{conn['remote_port']}"
                process = f"{conn['process_name']} ({conn['process_id']})"
                
                self.conn_tree.insert(
                    "", tk.END,
                    values=(local, remote, process, conn['state'])
                )
            
            self._log(f"Refreshed connections: {len(connections)} active")
            
        except Exception as e:
            self._log(f"Failed to refresh connections: {e}")
    
    # ===== TOOLS METHODS =====
    
    def _update_network_info(self):
        """Update network information display"""
        try:
            info = self.tools.get_network_info()
            
            info_text = f"""
Local IP Address: {info['local_ip']}
Public IP Address: {info['public_ip']}
Default Gateway: {info['gateway']}
DNS Servers: {', '.join(info['dns_servers'][:3])}

Network Adapters:
"""
            for adapter in info['network_adapters'][:3]:  # Show first 3
                info_text += f"\n  {adapter['name']}:\n"
                for addr in adapter['addresses']:
                    info_text += f"    • {addr['address']}/{addr['netmask']}\n"
            
            info_text += f"\nUpdated: {info['timestamp']}"
            
            self.network_info_text.config(state=tk.NORMAL)
            self.network_info_text.delete("1.0", tk.END)
            self.network_info_text.insert("1.0", info_text.strip())
            self.network_info_text.config(state=tk.DISABLED)
            
            # Update network info label
            local_ip = get_local_ip()
            self.network_info_label.config(text=f"Local Network: {local_ip}")
            
        except Exception as e:
            self._log(f"Failed to get network info: {e}")
    
    def _flush_dns(self):
        """Flush DNS cache"""
        if self.tools.flush_dns_cache():
            messagebox.showinfo("DNS Flush", "DNS cache flushed successfully.")
            self._log("DNS cache flushed")
        else:
            messagebox.showerror("DNS Flush", "Failed to flush DNS cache.")
            self._log("DNS flush failed")
    
    def _reset_network(self):
        """Reset network adapters"""
        if messagebox.askyesno("Reset Network", 
                              "Reset network adapters? This may temporarily disconnect your network."):
            if self.tools.reset_network():
                messagebox.showinfo("Reset Network", "Network adapters reset successfully.")
                self._log("Network adapters reset")
            else:
                messagebox.showerror("Reset Network", "Failed to reset network adapters.")
                self._log("Network reset failed")
    
    def _show_stats(self):
        """Show network statistics"""
        # Placeholder for network statistics
        messagebox.showinfo("Network Stats", "Network statistics feature will be implemented.")
    
    def _check_firewall(self):
        """Check firewall status"""
        from ..utils.windows_tools import check_firewall_status
        firewall = check_firewall_status()
        
        if firewall:
            status_text = "\n".join([f"{k}: {'✅ Enabled' if v else '❌ Disabled'}" 
                                    for k, v in firewall.items()])
            messagebox.showinfo("Firewall Status", f"Firewall Status:\n\n{status_text}")
            self._log("Firewall status checked")
        else:
            messagebox.showwarning("Firewall Status", "Could not retrieve firewall status.")
            self._log("Firewall check failed")
    
    def _log(self, message: str):
        """Add message to log"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_message = f"[{timestamp}] {message}\n"
        
        self.network_log_text.config(state=tk.NORMAL)
        self.network_log_text.insert(tk.END, log_message)
        self.network_log_text.see(tk.END)
        self.network_log_text.config(state=tk.DISABLED)
    
    def refresh(self):
        """Refresh network tab"""
        self._refresh_vpn_status()
        self._update_network_info()

if __name__ == "__main__":
    # Test the network tab
    root = tk.Tk()
    root.geometry("1200x700")
    
    notebook = ttk.Notebook(root)
    notebook.pack(fill=tk.BOTH, expand=True)
    
    network_tab = NetworkTab(notebook)
    notebook.add(network_tab.frame, text="Network Tools")
    
    root.mainloop()