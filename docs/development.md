Development — Running & Testing Locally

Environment
- Recommended Python: 3.10–3.12
- Create and activate a virtualenv (Windows):
  - python -m venv .venv
  - .\.venv\Scripts\activate

Install dependencies
- pip install --upgrade pip
- If you have a `requirements.txt.txt` file, run: pip install -r requirements.txt.txt
- For PCAP parsing and advanced heuristics, install scapy: pip install scapy
- Install test tooling: pip install pytest

Run tests
- Run all tests: python -m pytest -q
- Run a single test: python -m pytest tests/test_ai_cyber_helper.py::test_detect_dns_flood_sample -q

Run the GUI
- Start the main GUI module (if the project entry point is configured): python -m src.main
- Alternatively, open `src/gui/main_window.py` in an interactive session and create a Tk root:
  - import tkinter as tk
  - from src.gui.main_window import MainWindow
  - root = tk.Tk(); MainWindow(root); root.mainloop()

Adding samples and tests
- Add simple PCAP text samples into `data/sample_inputs/` (CSV-like lines) to exercise the fallback parser in tests.
- Write unit tests under `tests/` and follow the naming `test_*.py`.

CI
- GitHub Actions workflow lives at `.github/workflows/ci.yml` and runs pytest on push/PR.
- The CI installs `scapy` to enable PCAP-based tests on runner environments.

Convenience scripts
- Windows: `scripts/run_cyber_helper.bat.txt` (wraps `scripts/run_cyber_helper.py`)
  - Start GUI: `scripts\run_cyber_helper.bat.txt gui`
  - Quick scan: `scripts\run_cyber_helper.bat.txt scan 127.0.0.1 10.0.0.5`
  - Analyze PCAP/text sample: `scripts\run_cyber_helper.bat.txt pcap data/sample_inputs/portscan.txt`
- Cross-platform: `scripts/run_cyber_helper.py` — auto-detects and re-executes using `.venv` python if present. This ensures the project venv is used automatically when available.

Packaging
- Windows build script: `scripts/build_pyinstaller.bat.txt` (calls PyInstaller to create a single exe)
- Use `scripts/pyinstaller_entry.py` as the entrypoint for packaging (imports `src.main` and runs the app)
- CI packaging job: `.github/workflows/ci.yml` contains a `package` job that runs on `windows-latest` when pushing a tag that starts with `v` and uploads the built exe as an artifact.
Tagging & releases
- Use `scripts/push_tag.ps1` (PowerShell) or `scripts/push_tag.sh` (bash) to create and push annotated release tags.
  - PowerShell: `.	ools\push_tag.ps1 -TagName v0.1.0 -Message "v0.1.0 - Initial release"`
  - Bash: `./scripts/push_tag.sh v0.1.0 "v0.1.0 - Initial release"`
- The CI `package` job is triggered for tags that start with `v` (e.g., `v0.1.0`).Contributing
- Follow the project's code style and add unit tests for new detection heuristics or scanning features.
- Be mindful of privacy — do not add code that unintentionally exfiltrates or transmits sensitive scan outputs unless explicitly opt-in and documented.