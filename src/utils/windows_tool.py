"""
Windows-specific tools and utilities for Indentured Servant
"""
import os
import sys
import ctypes
import subprocess
import platform
import socket
import psutil
from pathlib import Path
from typing import List, Dict, Any, Optional

def is_admin() -> bool:
    """Check if running as administrator"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    """Restart the program with admin rights"""
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, " ".join(sys.argv), None, 1
    )
    sys.exit()

def get_windows_version() -> Dict[str, str]:
    """Get detailed Windows version information"""
    version_info = {
        'version': platform.version(),
        'release': platform.release(),
        'edition': 'Unknown'
    }
    
    try:
        # Try to get Windows edition
        import winreg
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                           r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
        
        try:
            edition, _ = winreg.QueryValueEx(key, "EditionID")
            version_info['edition'] = edition
        except:
            pass
        
        try:
            build, _ = winreg.QueryValueEx(key, "CurrentBuild")
            version_info['build'] = build
        except:
            pass
        
        winreg.CloseKey(key)
        
    except:
        pass
    
    return version_info

def run_powershell(command: str, timeout: int = 30) -> str:
    """
    Run a PowerShell command and return output
    
    Args:
        command: PowerShell command to run
        timeout: Timeout in seconds
        
    Returns:
        Command output as string
    """
    try:
        result = subprocess.run(
            ["powershell", "-Command", command],
            capture_output=True,
            text=True,
            timeout=timeout,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        return result.stdout if result.returncode == 0 else result.stderr
    except subprocess.TimeoutExpired:
        return "Command timed out"
    except Exception as e:
        return f"Error: {str(e)}"

def get_local_ip() -> str:
    """Get local IP address using PowerShell"""
    command = """
    $adapters = Get-NetIPAddress -AddressFamily IPv4 | 
                Where-Object {$_.IPAddress -notlike '169.254.*' -and 
                             $_.PrefixOrigin -eq 'Dhcp' -and 
                             $_.SuffixOrigin -eq 'Dhcp'} |
                Sort-Object InterfaceIndex
    
    if ($adapters) {
        $adapters[0].IPAddress
    } else {
        "127.0.0.1"
    }
    """
    
    result = run_powershell(command).strip()
    return result if result else "127.0.0.1"

def get_public_ip() -> Optional[str]:
    """Get public IP address"""
    import requests
    try:
        response = requests.get("https://api.ipify.org?format=json", timeout=5)
        return response.json()["ip"]
    except:
        return None

def get_system_info() -> Dict[str, Any]:
    """Get comprehensive system information"""
    info = {
        'os': 'Windows',
        'version': get_windows_version(),
        'hostname': socket.gethostname(),
        'local_ip': get_local_ip(),
        'public_ip': get_public_ip(),
        'cpu_count': os.cpu_count(),
        'memory': {},
        'disks': [],
        'network_adapters': []
    }
    
    # Memory info
    try:
        mem = psutil.virtual_memory()
        info['memory'] = {
            'total': mem.total,
            'available': mem.available,
            'percent': mem.percent,
            'used': mem.used
        }
    except:
        pass
    
    # Disk info
    try:
        for partition in psutil.disk_partitions():
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                info['disks'].append({
                    'device': partition.device,
                    'mountpoint': partition.mountpoint,
                    'fstype': partition.fstype,
                    'total': usage.total,
                    'used': usage.used,
                    'free': usage.free,
                    'percent': usage.percent
                })
            except:
                pass
    except:
        pass
    
    # Network adapters
    try:
        for name, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    info['network_adapters'].append({
                        'name': name,
                        'ip': addr.address,
                        'netmask': addr.netmask
                    })
    except:
        pass
    
    return info

def create_startup_shortcut(app_name: str = "Indentured Servant"):
    """Create shortcut in Startup folder"""
    try:
        startup_path = Path(os.environ.get('APPDATA')) / \
                      "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
        
        shortcut_path = startup_path / f"{app_name}.lnk"
        
        # Create shortcut using Windows Script Host
        vbs_script = f"""
        Set oWS = WScript.CreateObject("WScript.Shell")
        Set oLink = oWS.CreateShortcut("{shortcut_path}")
        oLink.TargetPath = "{sys.executable}"
        oLink.Arguments = "{' '.join(sys.argv)}"
        oLink.WorkingDirectory = "{os.getcwd()}"
        oLink.Description = "{app_name} - Cybersecurity Assistant"
        oLink.Save
        """
        
        vbs_file = Path("create_shortcut.vbs")
        vbs_file.write_text(vbs_script)
        subprocess.run(["cscript", str(vbs_file)], capture_output=True)
        vbs_file.unlink()
        
        return True
    except Exception as e:
        print(f"Failed to create startup shortcut: {e}")
        return False

def enable_windows_defender():
    """Enable Windows Defender real-time protection"""
    commands = [
        "Set-MpPreference -DisableRealtimeMonitoring $false",
        "Set-MpPreference -DisableBehaviorMonitoring $false",
        "Set-MpPreference -DisableBlockAtFirstSeen $false",
        "Set-MpPreference -DisableIOAVProtection $false",
        "Set-MpPreference -DisablePrivacyMode $false"
    ]
    
    results = []
    for cmd in commands:
        results.append(run_powershell(cmd))
    
    return results

def check_firewall_status() -> Dict[str, bool]:
    """Check Windows Firewall status for all profiles"""
    command = """
    Get-NetFirewallProfile | Select-Object Name, Enabled | ConvertTo-Json
    """
    
    result = run_powershell(command)
    try:
        import json
        profiles = json.loads(result)
        return {p['Name']: p['Enabled'] for p in profiles}
    except:
        return {}

def get_running_services() -> List[Dict[str, Any]]:
    """Get list of running Windows services"""
    command = """
    Get-Service | Where-Object {$_.Status -eq 'Running'} | 
    Select-Object Name, DisplayName, StartType | ConvertTo-Json
    """
    
    result = run_powershell(command)
    try:
        import json
        return json.loads(result)
    except:
        return []

def get_scheduled_tasks() -> List[Dict[str, Any]]:
    """Get list of scheduled tasks"""
    command = """
    Get-ScheduledTask | Where-Object {$_.State -eq 'Ready'} |
    Select-Object TaskName, TaskPath, Description | ConvertTo-Json
    """
    
    result = run_powershell(command)
    try:
        import json
        return json.loads(result)
    except:
        return []

def open_windows_security() -> bool:
    """Open Windows Security Center"""
    try:
        subprocess.run(["start", "windowsdefender:"], 
                      shell=True, check=True)
        return True
    except:
        return False

if __name__ == "__main__":
    # Test functions
    print("🔧 Testing Windows Tools...")
    print(f"Running as admin: {is_admin()}")
    print(f"Windows version: {get_windows_version()}")
    print(f"Local IP: {get_local_ip()}")
    print(f"Public IP: {get_public_ip()}")
    
    # System info
    info = get_system_info()
    print(f"\n💻 System Info:")
    print(f"  Hostname: {info['hostname']}")
    print(f"  CPU Cores: {info['cpu_count']}")
    if info['memory']:
        print(f"  Memory: {info['memory']['percent']}% used")
    
    # Firewall status
    firewall = check_firewall_status()
    print(f"\n🔥 Firewall Status:")
    for name, enabled in firewall.items():
        print(f"  {name}: {'✅ Enabled' if enabled else '❌ Disabled'}")