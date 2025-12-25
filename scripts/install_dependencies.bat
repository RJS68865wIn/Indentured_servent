@echo off
echo Installing Indentured Servant dependencies...
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo Python is not installed or not in PATH!
    echo Please install Python 3.8+ from python.org
    pause
    exit /b 1
)

REM Upgrade pip
echo Upgrading pip...
python -m pip install --upgrade pip

REM Install core dependencies
echo Installing core dependencies...
pip install cryptography requests psutil python-dotenv

REM Install Windows-specific dependencies
echo Installing Windows-specific dependencies...
pip install pywin32 pyinstaller

REM Optional dependencies
echo Installing optional dependencies...
pip install pandas matplotlib pillow

REM Create virtual environment (optional)
echo.
echo Would you like to create a virtual environment? (y/n)
set /p create_venv=
if /i "%create_venv%"=="y" (
    echo Creating virtual environment...
    python -m venv venv
    echo Virtual environment created.
    echo Activate with: venv\Scripts\activate
)

echo.
echo ✅ Installation complete!
echo.
echo To run the application:
echo   python run.py
echo.
pause