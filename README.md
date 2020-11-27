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


#### Detección de apagado de Firewall


#### Detección de apagado de Windows Defender


### Ejecución
Para la ejecución, posicionados en la carpeta, solamente ejecutamos el script de Perl

```
perl ids.pl
```