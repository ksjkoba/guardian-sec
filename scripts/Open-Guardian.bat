@echo off
title Guardian Dashboard
REM Double-click to open Guardian at http://127.0.0.1:8765
REM Requires WSL Ubuntu with ~/guardian set up.

wsl -d Ubuntu -e bash -lc "cd ~/guardian && ./scripts/open-guardian.sh"
if errorlevel 1 (
  echo.
  echo Could not launch Guardian. Check WSL Ubuntu and ~/guardian are set up.
  pause
)
