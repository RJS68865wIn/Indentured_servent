"""Network tools and helpers used by the Network tab.

This module provides lightweight, mostly self-contained implementations so the
packaged executable does not crash on missing imports. The functions focus on
safe inspection operations (no privileged actions) and return structured data
expected by the GUI.
"""

from __future__ import annotations

import socket
import time
import psutil
import platform
from dataclasses import dataclass, field
from typing import List, Dict, Any

from src.utils.windows_tools import (
	get_local_ip,
	get_public_ip,
	run_powershell,
)
from src.utils.logger import setup_logger


@dataclass
class NetworkDevice:
	ip: str
	hostname: str = ""
	mac: str = ""
	vendor: str = ""
	open_ports: List[int] = field(default_factory=list)
	os_guess: str = "Unknown"


class NetworkTools:
	"""Minimal network utilities used by the GUI.

	These implementations avoid heavy external dependencies and favor
	best-effort results over completeness so the packaged app remains stable.
	"""

	def __init__(self) -> None:
		self.logger = setup_logger("NetworkTools")

	# ----- VPN methods (placeholder implementations) -----
	def setup_wireguard_vpn(self, device_name: str, port: str) -> Dict[str, Any]:
		return {
			"success": False,
			"message": "WireGuard setup is not implemented in the packaged build.",
		}

	def start_wireguard_vpn(self) -> Dict[str, Any]:
		return {"success": False, "message": "VPN start not implemented."}

	def stop_wireguard_vpn(self) -> Dict[str, Any]:
		return {"success": False, "message": "VPN stop not implemented."}

	def get_vpn_status(self) -> Dict[str, Any]:
		return {"status": "unknown", "message": "VPN status not implemented."}

	# ----- Discovery and scanning -----
	def scan_local_network(self, timeout: float = 1.0) -> List[NetworkDevice]:
		"""Best-effort discovery: returns the local host as a single device."""
		try:
			local_ip = get_local_ip()
		except Exception:
			local_ip = "127.0.0.1"

		hostname = socket.gethostname()
		return [
			NetworkDevice(
				ip=local_ip,
				hostname=hostname,
				mac="",
				vendor="Local",  # Placeholder vendor
				open_ports=[],
				os_guess=platform.system(),
			)
		]

	def port_scan(self, target_ip: str, ports: List[int]) -> Dict[str, Any]:
		"""Simple TCP connect scan."""
		open_ports = []
		start = time.time()
		for port in ports:
			with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
				s.settimeout(0.5)
				try:
					result = s.connect_ex((target_ip, port))
					if result == 0:
						open_ports.append(
							{
								"port": port,
								"service": "tcp",
								"status": "open",
							}
						)
				except Exception:
					continue

		return {
			"target": target_ip,
			"ports_scanned": len(ports),
			"open_ports": open_ports,
			"scan_duration": time.time() - start,
		}

	def check_open_connections(self) -> List[Dict[str, Any]]:
		"""Return active TCP connections using psutil."""
		connections = []
		try:
			for conn in psutil.net_connections(kind="inet"):
				laddr = conn.laddr if conn.laddr else None
				raddr = conn.raddr if conn.raddr else None
				connections.append(
					{
						"local_address": laddr.ip if laddr else "",
						"local_port": laddr.port if laddr else "",
						"remote_address": raddr.ip if raddr else "",
						"remote_port": raddr.port if raddr else "",
						"state": conn.status,
						"process_id": conn.pid or "",
						"process_name": self._get_process_name(conn.pid),
					}
				)
		except Exception as exc:
			self.logger.error(f"Failed to read connections: {exc}")
		return connections

	def _get_process_name(self, pid: int | None) -> str:
		if not pid:
			return ""
		try:
			return psutil.Process(pid).name()
		except Exception:
			return ""

	def get_network_info(self) -> Dict[str, Any]:
		now = time.strftime("%Y-%m-%d %H:%M:%S")
		local_ip = get_local_ip()
		public_ip = get_public_ip() or "Unknown"

		adapters = []
		try:
			for name, addrs in psutil.net_if_addrs().items():
				ipv4_addrs = [
					{"address": a.address, "netmask": a.netmask}
					for a in addrs
					if a.family == socket.AF_INET
				]
				if ipv4_addrs:
					adapters.append({"name": name, "addresses": ipv4_addrs})
		except Exception as exc:
			self.logger.error(f"Failed to enumerate adapters: {exc}")

		return {
			"local_ip": local_ip,
			"public_ip": public_ip,
			"gateway": "Unknown",
			"dns_servers": [],
			"network_adapters": adapters,
			"timestamp": now,
		}

	# ----- Maintenance helpers -----
	def flush_dns_cache(self) -> bool:
		output = run_powershell("Clear-DnsClientCache")
		return "Cleared" in output or "success" in output.lower()

	def reset_network(self) -> bool:
		# Best-effort reset using PowerShell; may require admin privileges
		output = run_powershell("netsh int ip reset")
		return "Resetting" in output or "restart" in output.lower()
