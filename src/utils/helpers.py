"""Utility helpers for Indentured Servant.

These helpers are intentionally lightweight so they work in both source and
PyInstaller-frozen builds.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict


def ensure_dir(path: str | Path) -> Path:
	"""Create a directory if it does not exist and return the Path."""
	p = Path(path)
	p.mkdir(parents=True, exist_ok=True)
	return p


def read_json(path: str | Path, default: Dict[str, Any] | None = None) -> Dict[str, Any]:
	"""Read JSON safely, returning a default on failure."""
	p = Path(path)
	if not p.exists():
		return default or {}
	try:
		with p.open("r", encoding="utf-8") as f:
			return json.load(f)
	except Exception:
		return default or {}


def write_json(path: str | Path, data: Dict[str, Any]) -> None:
	"""Write JSON atomically with utf-8 encoding."""
	p = Path(path)
	ensure_dir(p.parent)
	tmp = p.with_suffix(p.suffix + ".tmp")
	with tmp.open("w", encoding="utf-8") as f:
		json.dump(data, f, indent=2)
	tmp.replace(p)


def format_bytes(num: int) -> str:
	"""Human-readable byte formatter."""
	for unit in ["B", "KB", "MB", "GB", "TB"]:
		if num < 1024.0:
			return f"{num:3.1f} {unit}"
		num /= 1024.0
	return f"{num:.1f} PB"


__all__ = [
	"ensure_dir",
	"read_json",
	"write_json",
	"format_bytes",
]
