@echo off
REM Windows Ransomware Detection Toolkit - launcher.
REM This tiny file exists only because Windows opens .ps1 files in Notepad on
REM double-click instead of running them. It just starts the one real script,
REM which shows its own menu (Quick / Full / Live monitor / Custom).
title Windows Ransomware Detection Toolkit
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0RansomwareToolkit.ps1"
echo.
pause
