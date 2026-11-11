@echo off
cd /d "%~dp0"
"runtime\python.exe" work\initio\dvd_bridge_runtime.py --stop
pause
