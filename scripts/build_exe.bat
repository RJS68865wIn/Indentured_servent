@echo off
setlocal

REM Build the Indentured Servant executable

REM Activate virtual environment if present
if exist "%~dp0..\.venv\Scripts\activate.bat" (
		call "%~dp0..\.venv\Scripts\activate.bat"
)

cd /d "%~dp0.."

python -m pip install -U pip
python -m pip install -r requirements.txt

pyinstaller --noconfirm --onefile --windowed --name indentured_servant ^
	--add-data "src;src" --add-data "config;config" ^
	scripts\pyinstaller_entry.py

echo Build complete. Executable is in the dist folder.
endlocal
