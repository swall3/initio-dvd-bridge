@echo off
cd /d "%~dp0"
"runtime\python.exe" work\initio\launch_dvd_autostart_setup.py Enable
pause
