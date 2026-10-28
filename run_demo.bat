@echo off
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo Run setup_demo.ps1 first.
  pause
  exit /b 1
)
.venv\Scripts\python.exe scripts\run_demo.py
pause
