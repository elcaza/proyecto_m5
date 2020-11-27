DIM objShell
set objShell=wscript.createObject("wscript.shell")
iReturn=objShell.Run("2_update_security.bat", 0, TRUE)