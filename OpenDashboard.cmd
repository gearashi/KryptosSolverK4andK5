@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0OpenDashboard.ps1" %*
exit /b %ERRORLEVEL%
