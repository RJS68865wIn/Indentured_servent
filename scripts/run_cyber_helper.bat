@echo off
REM Convenience script to run Indentured Servant Cyber Helper (calls cross-platform launcher)
REM Usage:
REM   run_cyber_helper.bat gui
REM   run_cyber_helper.bat scan 127.0.0.1 192.168.1.5
REM   run_cyber_helper.bat pcap "data/sample_inputs/portscan.txt"

n:: Forward arguments to the Python auto-venv launcher script
python scripts\run_cyber_helper.py %*

nendlocal 2>nul || exit /b 0




































endlocal 2>nul || exit /b 0
n:endecho   help        - Show this messageecho   pcap        - Analyze pcap or sample file: run_cyber_helper.bat pcap data/sample_inputs/portscan.txtecho   scan        - Run quick TCP connect scan: run_cyber_helper.bat scan 127.0.0.1echo   gui         - Start the GUIecho Usage: %~nx0 [gui|scan|pcap|help]
n:usage)  goto end  python -m src.ai_cyber_helper --pcap "%~1"  echo Analyzing PCAP: %~1  )    goto end    echo Usage: %~nx0 pcap path_to_pcap  if "%~1"=="" (  shift
nif /I "%1"=="pcap" ()  goto end  python -m src.ai_cyber_helper --scan %*  echo Scanning: %*  )    goto end    echo Usage: %~nx0 scan host1 host2  if "%*"=="" (  shift
nif /I "%1"=="scan" ()  goto end  python -m src.main  echo Starting GUI...
nif "%1"=="" goto usage
n
nif /I "%1"=="gui" ()  call ".venv\Scripts\activate.bat"if exist ".venv\Scripts\activate.bat" (n:: Attempt to activate local venv if present