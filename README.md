# Proyecto módulo 5
IDS de Host para detectar software de minado de criptomonedas comúnmente utilizado en el malware, a través del análisis de indicadores de compromiso (IoC).

## Desarrollo del Malware
Malware de minado que permite:
+ Ejecutar minado de Litecoin
+ Desactivar firewall
+ Desactivar antivirus
+ Creación de reglas de firewall para permitir todas las conexiones 
+ Desactivar el UAC (User Account Control) de Windows 
+ Descargar de Internet un archivo específico 
+ Ejecutar un comando en Windows 
+ Modificación del archivo hosts para hacer pharming 
+ Habilita ASLR
+ Lectura de instrucciones a partir de esteganografía en imagenes

Este malware no se ejecuta dentro de máquinas virtuales para evitar su análisis

### Ejecución
Para su ejecución unicamente debe ejecutar con privilegios de administrador el archivo .exe

## Desarrollo del IDS
