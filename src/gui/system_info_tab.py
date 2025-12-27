"""
System Information Tab
Comprehensive system information display
"""
import tkinter as tk
from tkinter import ttk
import platform
import psutil
import socket
import subprocess
import json
from datetime import datetime, timedelta
import os
import sys

try:
    import winreg
    import win32api
    import win32con
    HAS_WIN32 = True
except ImportError:
    HAS_WIN32 = False

from src.utils.logger import setup_logger
from src.utils.helpers import format_bytes


class SystemInfoTab:
    """System information display tab"""
    
    def __init__(self, parent):
        self.parent = parent
        self.frame = ttk.Frame(parent)
        self.logger = setup_logger()
        
        self._setup_ui()
        self._load_system_info()
    
    def _setup_ui(self):
        """Setup the user interface"""
        # Create main scrollable frame
        main_container = ttk.Frame(self.frame)
        main_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create canvas and scrollbar
        canvas = tk.Canvas(main_container, highlightthickness=0)
        scrollbar = ttk.Scrollbar(main_container, orient=tk.VERTICAL, command=canvas.yview)
        self.scrollable_frame = ttk.Frame(canvas)
        
        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Bind mousewheel
        canvas.bind_all("<MouseWheel>", lambda e: canvas.yview_scroll(int(-1 * (e.delta / 120)), "units"))
        
        # Title
        title_frame = ttk.Frame(self.scrollable_frame)
        title_frame.pack(fill=tk.X, pady=(0, 20))
        
        ttk.Label(
            title_frame,
            text="💻 System Information",
            font=("Segoe UI", 20, "bold")
        ).pack(side=tk.LEFT)
        
        ttk.Button(
            title_frame,
            text="🔄 Refresh",
            command=self._load_system_info,
            width=15
        ).pack(side=tk.RIGHT)
        
        # Create information sections
        self._create_os_section()
        self._create_hardware_section()
        self._create_cpu_section()
        self._create_memory_section()
        self._create_disk_section()
        self._create_network_section()
        self._create_boot_section()
        self._create_python_section()
        if HAS_WIN32:
            self._create_windows_section()
    
    def _create_info_tree(self, parent, title, height=8):
        """Create a treeview for displaying information"""
        frame = ttk.LabelFrame(parent, text=title, padding=15)
        frame.pack(fill=tk.BOTH, expand=True, pady=(0, 15))
        
        columns = ("Property", "Value")
        tree = ttk.Treeview(
            frame,
            columns=columns,
            show="tree headings",
            height=height
        )
        
        tree.heading("#0", text="", anchor=tk.W)
        tree.column("#0", width=0, stretch=False)
        tree.heading("Property", text="Property", anchor=tk.W)
        tree.column("Property", anchor=tk.W, width=250)
        tree.heading("Value", text="Value", anchor=tk.W)
        tree.column("Value", anchor=tk.W, width=400)
        
        tree_scroll = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=tree.yview)
        tree.configure(yscrollcommand=tree_scroll.set)
        
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        return tree
    
    def _create_os_section(self):
        """Create OS information section"""
        self.os_tree = self._create_info_tree(self.scrollable_frame, "🖥️ Operating System", height=10)
    
    def _create_hardware_section(self):
        """Create hardware information section"""
        self.hw_tree = self._create_info_tree(self.scrollable_frame, "⚙️ Hardware", height=8)
    
    def _create_cpu_section(self):
        """Create CPU information section"""
        self.cpu_tree = self._create_info_tree(self.scrollable_frame, "🔧 Processor", height=10)
    
    def _create_memory_section(self):
        """Create memory information section"""
        self.mem_tree = self._create_info_tree(self.scrollable_frame, "🧠 Memory", height=8)
    
    def _create_disk_section(self):
        """Create disk information section"""
        self.disk_tree = self._create_info_tree(self.scrollable_frame, "💾 Disks", height=12)
    
    def _create_network_section(self):
        """Create network information section"""
        self.net_tree = self._create_info_tree(self.scrollable_frame, "🌐 Network", height=10)
    
    def _create_boot_section(self):
        """Create boot information section"""
        self.boot_tree = self._create_info_tree(self.scrollable_frame, "⚡ Boot & Performance", height=6)
    
    def _create_python_section(self):
        """Create Python environment section"""
        self.python_tree = self._create_info_tree(self.scrollable_frame, "🐍 Python Environment", height=8)
    
    def _create_windows_section(self):
        """Create Windows-specific information section"""
        self.win_tree = self._create_info_tree(self.scrollable_frame, "🪟 Windows Details", height=10)
    
    def _add_item(self, tree, property_name, value):
        """Add an item to a treeview"""
        tree.insert("", tk.END, values=(property_name, str(value)))
    
    def _load_system_info(self):
        """Load all system information"""
        self._load_os_info()
        self._load_hardware_info()
        self._load_cpu_info()
        self._load_memory_info()
        self._load_disk_info()
        self._load_network_info()
        self._load_boot_info()
        self._load_python_info()
        if HAS_WIN32:
            self._load_windows_info()
        
        self.logger.info("System information loaded")
    
    def _load_os_info(self):
        """Load operating system information"""
        # Clear existing items
        for item in self.os_tree.get_children():
            self.os_tree.delete(item)
        
        try:
            uname = platform.uname()
            self._add_item(self.os_tree, "Operating System", f"{uname.system} {uname.release}")
            self._add_item(self.os_tree, "OS Version", uname.version)
            self._add_item(self.os_tree, "OS Build", platform.platform())
            self._add_item(self.os_tree, "Computer Name", uname.node)
            self._add_item(self.os_tree, "Machine Type", uname.machine)
            self._add_item(self.os_tree, "Processor", uname.processor)
            
            # Windows version details
            if platform.system() == "Windows":
                try:
                    import winreg
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
                    product_name = winreg.QueryValueEx(key, "ProductName")[0]
                    build = winreg.QueryValueEx(key, "CurrentBuild")[0]
                    display_version = winreg.QueryValueEx(key, "DisplayVersion")[0]
                    winreg.CloseKey(key)
                    
                    self._add_item(self.os_tree, "Windows Edition", product_name)
                    self._add_item(self.os_tree, "Build Number", build)
                    self._add_item(self.os_tree, "Display Version", display_version)
                except:
                    pass
            
            self._add_item(self.os_tree, "Architecture", platform.architecture()[0])
            self._add_item(self.os_tree, "System Encoding", sys.getdefaultencoding())
            
        except Exception as e:
            self.logger.error(f"Error loading OS info: {e}")
    
    def _load_hardware_info(self):
        """Load hardware information"""
        for item in self.hw_tree.get_children():
            self.hw_tree.delete(item)
        
        try:
            # Physical cores
            physical_cores = psutil.cpu_count(logical=False)
            logical_cores = psutil.cpu_count(logical=True)
            
            self._add_item(self.hw_tree, "Physical CPU Cores", physical_cores)
            self._add_item(self.hw_tree, "Logical CPU Cores", logical_cores)
            
            # Total RAM
            mem = psutil.virtual_memory()
            self._add_item(self.hw_tree, "Total RAM", format_bytes(mem.total))
            
            # Total Disk Space
            total_disk = sum([partition.usage().total for partition in psutil.disk_partitions() if 'cdrom' not in partition.opts.lower()])
            self._add_item(self.hw_tree, "Total Disk Space", format_bytes(total_disk))
            
            # GPU Info (Windows)
            if platform.system() == "Windows":
                try:
                    import subprocess
                    result = subprocess.run(
                        ["wmic", "path", "win32_VideoController", "get", "name"],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    gpus = [line.strip() for line in result.stdout.split('\n') if line.strip() and line.strip() != "Name"]
                    for i, gpu in enumerate(gpus, 1):
                        self._add_item(self.hw_tree, f"GPU {i}", gpu)
                except:
                    pass
            
        except Exception as e:
            self.logger.error(f"Error loading hardware info: {e}")
    
    def _load_cpu_info(self):
        """Load CPU information"""
        for item in self.cpu_tree.get_children():
            self.cpu_tree.delete(item)
        
        try:
            self._add_item(self.cpu_tree, "Processor", platform.processor())
            self._add_item(self.cpu_tree, "Physical Cores", psutil.cpu_count(logical=False))
            self._add_item(self.cpu_tree, "Logical Cores", psutil.cpu_count(logical=True))
            
            # CPU Frequency
            freq = psutil.cpu_freq()
            if freq:
                self._add_item(self.cpu_tree, "Max Frequency", f"{freq.max:.2f} MHz")
                self._add_item(self.cpu_tree, "Min Frequency", f"{freq.min:.2f} MHz")
                self._add_item(self.cpu_tree, "Current Frequency", f"{freq.current:.2f} MHz")
            
            # CPU Usage
            self._add_item(self.cpu_tree, "Total CPU Usage", f"{psutil.cpu_percent(interval=1)}%")
            
            # Per-core usage
            per_core = psutil.cpu_percent(interval=1, percpu=True)
            for i, usage in enumerate(per_core, 1):
                self._add_item(self.cpu_tree, f"Core {i} Usage", f"{usage}%")
            
        except Exception as e:
            self.logger.error(f"Error loading CPU info: {e}")
    
    def _load_memory_info(self):
        """Load memory information"""
        for item in self.mem_tree.get_children():
            self.mem_tree.delete(item)
        
        try:
            mem = psutil.virtual_memory()
            
            self._add_item(self.mem_tree, "Total Memory", format_bytes(mem.total))
            self._add_item(self.mem_tree, "Available Memory", format_bytes(mem.available))
            self._add_item(self.mem_tree, "Used Memory", format_bytes(mem.used))
            self._add_item(self.mem_tree, "Memory Usage", f"{mem.percent}%")
            
            # Swap/Page file
            swap = psutil.swap_memory()
            self._add_item(self.mem_tree, "Swap Total", format_bytes(swap.total))
            self._add_item(self.mem_tree, "Swap Used", format_bytes(swap.used))
            self._add_item(self.mem_tree, "Swap Free", format_bytes(swap.free))
            self._add_item(self.mem_tree, "Swap Usage", f"{swap.percent}%")
            
        except Exception as e:
            self.logger.error(f"Error loading memory info: {e}")
    
    def _load_disk_info(self):
        """Load disk information"""
        for item in self.disk_tree.get_children():
            self.disk_tree.delete(item)
        
        try:
            partitions = psutil.disk_partitions()
            
            for partition in partitions:
                if 'cdrom' in partition.opts.lower():
                    continue
                
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    
                    self._add_item(self.disk_tree, f"{partition.device} - Total", format_bytes(usage.total))
                    self._add_item(self.disk_tree, f"{partition.device} - Used", format_bytes(usage.used))
                    self._add_item(self.disk_tree, f"{partition.device} - Free", format_bytes(usage.free))
                    self._add_item(self.disk_tree, f"{partition.device} - Usage", f"{usage.percent}%")
                    self._add_item(self.disk_tree, f"{partition.device} - Type", partition.fstype)
                except PermissionError:
                    continue
            
        except Exception as e:
            self.logger.error(f"Error loading disk info: {e}")
    
    def _load_network_info(self):
        """Load network information"""
        for item in self.net_tree.get_children():
            self.net_tree.delete(item)
        
        try:
            # Hostname and IP
            hostname = socket.gethostname()
            self._add_item(self.net_tree, "Hostname", hostname)
            
            try:
                local_ip = socket.gethostbyname(hostname)
                self._add_item(self.net_tree, "Local IP", local_ip)
            except:
                pass
            
            # Network interfaces
            if_addrs = psutil.net_if_addrs()
            for interface_name, addresses in if_addrs.items():
                for addr in addresses:
                    if addr.family == socket.AF_INET:  # IPv4
                        self._add_item(self.net_tree, f"{interface_name} - IPv4", addr.address)
                    elif addr.family == socket.AF_INET6:  # IPv6
                        self._add_item(self.net_tree, f"{interface_name} - IPv6", addr.address[:30] + "...")
            
            # Network stats
            net_io = psutil.net_io_counters()
            self._add_item(self.net_tree, "Bytes Sent", format_bytes(net_io.bytes_sent))
            self._add_item(self.net_tree, "Bytes Received", format_bytes(net_io.bytes_recv))
            
        except Exception as e:
            self.logger.error(f"Error loading network info: {e}")
    
    def _load_boot_info(self):
        """Load boot and performance information"""
        for item in self.boot_tree.get_children():
            self.boot_tree.delete(item)
        
        try:
            # Boot time
            boot_time = datetime.fromtimestamp(psutil.boot_time())
            uptime = datetime.now() - boot_time
            
            self._add_item(self.boot_tree, "Boot Time", boot_time.strftime("%Y-%m-%d %H:%M:%S"))
            self._add_item(self.boot_tree, "Uptime", str(uptime).split('.')[0])
            
            # Load average (if available)
            try:
                load_avg = psutil.getloadavg()
                self._add_item(self.boot_tree, "Load Average (1m)", f"{load_avg[0]:.2f}")
                self._add_item(self.boot_tree, "Load Average (5m)", f"{load_avg[1]:.2f}")
                self._add_item(self.boot_tree, "Load Average (15m)", f"{load_avg[2]:.2f}")
            except:
                pass
            
            # Running processes
            self._add_item(self.boot_tree, "Running Processes", len(psutil.pids()))
            
        except Exception as e:
            self.logger.error(f"Error loading boot info: {e}")
    
    def _load_python_info(self):
        """Load Python environment information"""
        for item in self.python_tree.get_children():
            self.python_tree.delete(item)
        
        try:
            self._add_item(self.python_tree, "Python Version", platform.python_version())
            self._add_item(self.python_tree, "Python Build", platform.python_build()[0])
            self._add_item(self.python_tree, "Python Compiler", platform.python_compiler())
            self._add_item(self.python_tree, "Python Implementation", platform.python_implementation())
            self._add_item(self.python_tree, "Executable Path", sys.executable)
            self._add_item(self.python_tree, "Prefix", sys.prefix)
            self._add_item(self.python_tree, "Base Prefix", sys.base_prefix)
            
            # Check if running from frozen exe
            if getattr(sys, 'frozen', False):
                self._add_item(self.python_tree, "Frozen", "Yes (PyInstaller)")
                self._add_item(self.python_tree, "MEIPASS", sys._MEIPASS)
            else:
                self._add_item(self.python_tree, "Frozen", "No")
            
        except Exception as e:
            self.logger.error(f"Error loading Python info: {e}")
    
    def _load_windows_info(self):
        """Load Windows-specific information"""
        if not HAS_WIN32:
            return
        
        for item in self.win_tree.get_children():
            self.win_tree.delete(item)
        
        try:
            # Windows version from registry
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
            
            try:
                install_date = winreg.QueryValueEx(key, "InstallDate")[0]
                install_datetime = datetime.fromtimestamp(install_date)
                self._add_item(self.win_tree, "Install Date", install_datetime.strftime("%Y-%m-%d %H:%M:%S"))
            except:
                pass
            
            try:
                registered_owner = winreg.QueryValueEx(key, "RegisteredOwner")[0]
                self._add_item(self.win_tree, "Registered Owner", registered_owner)
            except:
                pass
            
            try:
                registered_org = winreg.QueryValueEx(key, "RegisteredOrganization")[0]
                if registered_org:
                    self._add_item(self.win_tree, "Registered Organization", registered_org)
            except:
                pass
            
            try:
                product_id = winreg.QueryValueEx(key, "ProductId")[0]
                self._add_item(self.win_tree, "Product ID", product_id)
            except:
                pass
            
            winreg.CloseKey(key)
            
            # System directory
            self._add_item(self.win_tree, "System Directory", os.environ.get('SystemRoot', 'Unknown'))
            self._add_item(self.win_tree, "Program Files", os.environ.get('ProgramFiles', 'Unknown'))
            self._add_item(self.win_tree, "User Profile", os.environ.get('USERPROFILE', 'Unknown'))
            
            # User info
            self._add_item(self.win_tree, "Username", os.environ.get('USERNAME', 'Unknown'))
            self._add_item(self.win_tree, "Computer Domain", os.environ.get('USERDOMAIN', 'Unknown'))
            
        except Exception as e:
            self.logger.error(f"Error loading Windows info: {e}")
