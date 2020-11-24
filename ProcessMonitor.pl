use strict;
use warnings;
use Win32::OLE('in');
use Win32::Process::List;

#Variables globales / constructores del sistema
my $processorCount;     #Para obtener los procesadores del sistema
my $statsQuery;         #Para crear las queries al sig objeto
my $objWMIService = Win32::OLE->GetObject("winmgmts://./root/cimv2") or die "WMI fallido\n";  #Se crea objeto del sistema
my $P = Win32::Process::List->new() or die "Lista fallida\n";    #Se crea una lista de procesos
# Funcion ´rincipal para el monitoreo de procesos. Se mete en un ciclo while para que se realice más d euna vez
sub main(){
    my %list = $P->GetProcesses();
    foreach my $key ( keys %list ) 
    {
        my $process = substr $list{$key}, 0, -4; #print $process."\n";
        #$statsQuery="select * from Win32_PerfRawData_PerfProc_Process where IDProcess=".$$; #Usando PID
        $statsQuery="select * from Win32_PerfRawData_PerfProc_Process where Name='".$process."'"; #Nombres de proceso sin .exe #print $statsQuery;
        ProcNums();
        GetProcessInfo(10,10);
    }
}
# Obtiene datos para el cálculo de datos
sub ProcNums(){
    my $logicalProcs = $objWMIService->ExecQuery("select NumberOfLogicalProcessors from Win32_ComputerSystem");     #Obteneos los procesadores lógicos
    foreach my $logicalProc (in $logicalProcs)
    { 
        $processorCount = $logicalProc->{NumberOfLogicalProcessors};
    }
}
# Obtiene los datos del proceso
sub GetProcessInfo(){
    my $limit = shift;        #Cantidad de calculos que realiza por proceso
    my $tolerancia = shift;   #Porcentaje de CPU que levanta alerta


    my $processingTime=0;
    my $timeStamp=0;
    my $cpu=0;
    my $cpumin=0;
    my $ram=0;
    my $procName;

    while($limit != 0)
    {
        #Se obtiene el volcado de l ainformación del proceso
        my $procDump = $objWMIService->ExecQuery($statsQuery);
        #Se obtienen los datos que nos competen del proceso
        foreach my $procData( in $procDump){
            $procName = $procData->{Name};
            $cpumin = CPUutil($processingTime,$procData->{PercentProcessorTime},$timeStamp,$procData->{TimeStamp_Sys100NS});
            $processingTime = $procData->{PercentProcessorTime};
            $timeStamp = $procData->{TimeStamp_Sys100NS};
            $ram = $procData->{WorkingSetPrivate};
        }
        #Se guarda el valor máximo en CPU (para detectar el minero) de las rondas
        if ($cpumin > $cpu){
            $cpu = $cpumin;
        }
        #Se pasa a la sig ronda
        $limit -= 1;
    }
    # Se revisa si ha superado la tolerancia establecida
    if ($cpu > $tolerancia){
        print "Nombre de proceso :".$procName.", MaxCPU:".sprintf("%.4f",$cpu)."%, RAM:".$ram."\n"; #Mensaje a escribir
    }
}
#Obtiene el dato correcto del uso de CPU
sub CPUutil(){
    #Se pasan los calores de los argumentos a las variables
    my $oldProcData = shift;
    my $newProcData = shift;
    my $oldProcTime = shift;
    my $newProcTime = shift;
    #Se obtiene el valor de CPU
    my $procData = ($newProcData - $oldProcData);
    my $procTime = ($newProcTime - $oldProcTime);
    my $util=(($procData/$procTime)*100)/$processorCount;
    return $util;
}

#Corre la función del monitoreo
main();