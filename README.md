# Proyecto de módulo 5
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
+ Lectura de instrucciones a partir de esteganografía en imagenes alojadas en github
+ Codificación de instrucciones en base64

Este malware no se ejecuta dentro de máquinas virtuales para evitar su análisis

### Ejecución
```
Para su ejecución unicamente debe ejecutar con privilegios de administrador el archivo .exe
```

+ Provisionalmente no funciona la persistencia, debido a que al utilizar esteganografía requiere de utilizar descargas de imagenes, que se conflictua con los permisos de la carpeta.

## Desarrollo del IDS
El IDS permite la detección de software de minado mediante las siguientes técnicas:
+ Uso anomalo de CPU
+ Tráfico de la red
+ Conexiones establecidas
+ Análisis de la memoria RAM
+ Análisis de ASEPs
+ Detección de apagado de Firewall
+ Detección de apagado de Windows Defender

El IDS es de fácil configuración gracias a su `config.json` en que se pueden definir sus umbrales a utilizar

### Requerimientos
Se requiere tener perl, este se puede obtener desde:
+ http://strawberryperl.com/releases.html

Se requiere la instalación de los siguientes módulos:
+ Net::Pcap
+ Win32::OLE
+ Win32::GUI
+ Win32::Process::List
+ JSON::Parse
+ Win32::PowerShell::IPC
+ Win32::GUI
+ Data::Dumper
+ lib
+ JSON::MaybeXS
+ Scalar::Util
+ Digest::file
+ HTTP::Tiny;
+ Array::Utils

### Funciones
A continuación se describen las funcionalidades del HIDS:

#### Uso anomalo de CPU
Desde el archivo de configuración se define la cantidad de rondas usadas para el análisis de procesos así como el procentaje minimo de uso para el reporte de programas anómalos. 

Se busca dentro de los procesos del sistema aquella que cumpla la condición y se vuelca la información del proceso (Uso de CPU, uso de RAM, PID). Esta información se usa posteriormente en el análisis de memoria RAM y conexiones establecidas.

#### Tráfico de la red
Se hace uso de Wireshark para la obtención de paquetes pcap. Estos son filtrados y analizados para obtener archivos maliciosos que se estén transmitiendo por TCP.

#### Conexiones establecidas
Se hace el filtrado de la salida de netstat para obtener las conexiones abiertas. Estas se asocian luego con las direcciones consultadas por el proceso anómalo para corroborar un enlace persistente por la red.

#### Análisis de la memoria RAM
Usando la herramienta de strings2, se hace el volcado de memoria del proceso. Dentro del mismo, se buscan URLs y se hcae su cuenta. Esto se exporta como un archivo json para la consulta realizada en conexiones establecidas


#### Análisis de ASEPs
Se hace un analisis de las rutas utilizadas para localizar programas que queremos que sean ejecutados en cada inicio de sesión de usuario o de manera global en todo el equipo. Una vez teniendo nuestras rutas, se realiza una verificación en la que podemos monitorear cuando un archivo "sospechoso" de tipo ejecutable (.exe, .vbs, .ps1, etc.) es creado en estas direcciones, eso es alertado y reflejado en la bitacora.

#### Análisis de Archivos y Directorios (FIM)
Se hace un monitoreo de la integridad de archivos especificos como el archivo "host" el cual podría implicar un intento de pharming, cada que se realiza una modificación en estos archivos se muestra en la bitacora el nombre del archivo junto con dos hash md5, el primero será el hash original y el segundo será el hash después de la modificación. Para el monitoreo de directorios se especifican directorios como "%appdata%", en estos directorios suelen colocarse las muestras de malware, este monitoreo verifica si se crean archivos que pordían ser archivos con extensiones de archivos que pueden ser ejecutados (.exe, .vbs, .ps1, etc.). De igual manera se monitorea si un archivo de estos es eliminado. Una vez se detecta al alguna de estas acciones se escribe en bitacora.

#### Prueba de archivo en sandbox VirusTotal
Si se encuentra habilitada esta opción, se obtiene el hash md5 de la muestra que se enviará a la sandbox y se realiza la petición, esta petición es procesada y se obtiene el resultado de conicidencias en la sandbox, el resultado es escrito en la bitacora.

#### Detección de apagado de Firewall


#### Detección de apagado de Windows Defender


### Ejecución
Para la ejecución, posicionados en la carpeta, solamente ejecutamos el script de Perl

```
perl ids.pl
```