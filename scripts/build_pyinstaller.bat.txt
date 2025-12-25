@echo off
REM Build a Windows standalone executable using PyInstaller (local venv preferred)
python -m pip install --upgrade pip
pip install pyinstaller
pyinstaller --noconfirm --onefile --name indentured_servant scripts\pyinstaller_entry.py
if %ERRORLEVEL% neq 0 (
  echo PyInstaller build failed
  exit /b %ERRORLEVEL%
)

necho Build complete: dist\indentured_servant.exe