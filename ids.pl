# Proyecto de Modulo - IDS de Host 
# Castillo Montes Alan
# Liberos Sanchez Jose Angel
# Martinez Balderas Jose Antonio
use Win32::GUI; # cpanm Win32::GUI
use Data::Dumper;
use lib qw(..);
use warnings;
use JSON::MaybeXS qw(encode_json decode_json);
use Scalar::Util qw(reftype);
use Digest::file qw(digest_file_hex); 
use HTTP::Tiny; # peticiones 
# comparacion de arreglos
use Array::Utils qw(:all); # cpanm Array::Utils
# process monitor
use Win32::OLE('in');
use Win32::Process::List;

# ejecucion de comandos de powershell
use Win32::PowerShell::IPC;
#use lib 'C:\\Strawberry\\cpan\\build\\Win32-PowerShell-IPC-0.02-0\\lib\Win32\PowerShell\\'; por si acaso

# archivo de bitacora
my $log_file = get_time();
$log_file =~ s/( |:)/_/g;

# archivo de configuracion
my $file = "config.json";
my $msg = "";

# proces monitor
#Variables globales / constructores del sistema
my $processorCount;     #Para obtener los procesadores del sistema
my $statsQuery;         #Para crear las queries al sig objeto
my $objWMIService = Win32::OLE->GetObject("winmgmts://./root/cimv2") or die "WMI fallido\n";  #Se crea objeto del sistema
my $P = Win32::Process::List->new() or die "Lista fallida\n";    #Se crea una lista de procesos
my $flag = 0;
my @security;

sub main{
    # Se verifica que el archivo de configuracion se encuentre disponible, de lo 
    # contrario termina la ejecucion el archivo
    unless(-e $file){
        $msg = "No existe el archivo de configuracion '$file'";
        message_box($msg, "Error"); # muestra una ventana con un mensaje de error
        die $msg;
    } else {
        # Leemos el archivo de configuracion
        my $json_text = do { open my $fh, '<', $file; local $/; <$fh> }; # obtiene el contenido del archivo de configuracion
        my $text = decode_json($json_text); # decodificamos el contenido
        my @files_list = @{$text->{ARCHIVOS}}; # obtenemos la lista de los archivos
        my @dir_list = @{$text->{DIRECTORIOS}}; # obtenemos la lista de directorios a monitorear
        my %aseps_hash = %{$text->{ASEP}}; # obtenemos un hash con los ASEPs
        my %iocs_hash = %{$text->{IoCs}}; # obtenemos un hash con los iocs
        my $flag_virus = $text->{FLAG}; # obtenemos el valor de la bandera para consultar virus total

        @security = @{$iocs_hash{"WindowsSecurity"}};
        my $check_windows_firewall = do { open my $fh, '<', "auxiliares\\check_firewall.txt"; local $/; <$fh> };
        my $check_windows_defender = do { open my $fh, '<', "auxiliares\\check_defender.txt"; local $/; <$fh> };

        #print "@security";
=pod
        my $process_name = "\\Microsoft\\XblGameSave\\";
        my $method = "TaskPath";
        # Función de powershell para corroborar la existencia de tareas programadas
        my $powershell_scheduledTask = '
        function exists_scheduledTask {

            param (
                $name,
                $method
            )
            $taskExists = "";
            if ($method -eq "TaskName"){
                $taskExists = Get-ScheduledTask | Where-Object {$_.TaskName -like $name }
            } 
            if ($method -eq "TaskPath"){
                $taskExists = Get-ScheduledTask | Where-Object {$_.TaskPath -like $name }
            }

            if($taskExists) {
            # echo "Existe"; 
            return 1;
            } else {
            # echo "No existe";
            return 0;
            }

            # Write-Output $name $method

        }
        exists_scheduledTask ';

        my $pw_args = "$process_name $method\n";
        $powershell_scheduledTask = "$powershell_scheduledTask $pw_args";
=cut

        # lista de hashes de los archivos especificados en el archivo de configuracion
        my %hash_files = get_hashes(@files_list);
        my %dirs = get_files_in_dir(get_path_dirs(@dir_list));
        my %rutas = get_files_in_dir(get_path_dirs(@{$aseps_hash{"rutas"}}));
        my @cpu = @{$iocs_hash{"cpu"}};

        # ciclo infinito es el core del programa, aqui van todas las funciones que se van a estar
        # ejecutando
        # creamos el hilo
        my $pid = fork();
        die if not defined $pid;
        while(1){
            if ($pid){
                check_files(\%hash_files);
                check_dirs("DIRECTORIOS", $flag_virus, \%dirs);
                check_dirs("ASEPS[rutas]", $flag_virus, \%rutas);
                windows_security(@security[0], @security[1], $check_windows_firewall, $check_windows_defender);
                #task_schedule($powershell_scheduledTask, $process_name);
            } else {
                #sleep(1000);
                process_monitor(@cpu);
                ram_analizer();
                network_monitor();
                # asdasd
            }
        }
    }
}

# Funcion que nos muestra una ventana con un mensaje en pantalla
# Recibe:
#   $mensaje -> mensaje a mostrar
#   $titulo -> titulo de la ventana
sub message_box{
    my ($mensaje, $titulo) = @_;
    $box = Win32::GUI::MessageBox(undef, "$mensaje", "$titulo", MB_OK); # genera la ventana que muestra al usuario
}

# Funcion que obtiene los hashes de una lista de archivos, si estos archivos se modifican
# Recibe:
#   %files_hashes -> hash con los hashes de los archivos
sub check_files{
    my %files_hashes = %{$_[0]};

    foreach my $file(keys %files_hashes){
        my $md5 = $files_hashes{$file}{'MD5'}; # obtenemos el md5 original
        my $sha256 = $files_hashes{$file}{'SHA256'}; # obtenemos el sha256 original
        my $actual_md5 = digest_file_hex($file, "MD5"); # obtenemos el md5 mas actual
        my $actual_sha256 = digest_file_hex($file, "SHA-256"); # obtenemos el sha256 mas actual

        # validamos que el hash sea el mismo
        unless($actual_md5 eq $md5 && $actual_sha256 eq $sha256){
            # escribimos en bitacora el cambio
            write_log("FILE", "Se modifico el hash del archivo '$file' $md5 => $actual_md5");
            # igualamos los hashes a la version mas actual
            $files_hashes{$file}{'MD5'} = $actual_md5; 
            $files_hashes{$file}{'SHA256'} = $actual_sha256;
        }
    }
}

# funcion que retorna los hashes de una lista de archivos
# Recibe:
#   @files -> lista de archivos
# Retorna: 
#   %files_hashes -> hash md5 y sha256 del archivo, la llave es el nombre del archivo
sub get_hashes{
    my @files = @_;
    my %files_hashes;
    # obtenemos los hashes de todos los archivos y los almacenamos en un hash
    foreach my $file(@files){
        $files_hashes{"$file"}{"MD5"} = digest_file_hex($file, "MD5"); # obtenemos el MD5
        $files_hashes{"$file"}{"SHA256"} = digest_file_hex($file, "SHA-256"); # obtenemos el SHA256
    }

    return %files_hashes;
}

# Realiza una peticion hacia virustotal, recibe el hash de la muestra a buscar
# Recibe:
#   $busqueda -> hash del archivo a consutar
#   $tipo -> tipo de elemento en el archivo de configuracion
#   $file -> nombre del archivo
sub send_virustotal{
    my ($busqueda, $tipo, $file) = @_; 
    my $api = '13f4b9f6a3ca612e7651e9f88f0f0eb892cdc9d50ae16de9d4f19ed2eeb5d2e9'; # api de virustotal
    my $url = 'https://www.virustotal.com/vtapi/v2/file/report'; # url de virustotal
    my $ua = HTTP::Tiny->new;
    my $resultado;

    # establecemos los valores con los que se hace la peticion a virustotal
    my $form = {
        resource => "$busqueda", 
        apikey => "$api",
    };

    # generamos la respuesta 
    my $response = $ua->post_form( $url, $form );
    my $data = decode_json($response->{'content'}); # decodificamos la respuesta obtenida y la almacenamos en dorma de json
    my $total = $data->{total}; # obtenemos el total de muestras
    my $positivo = $data->{positives}; # obtenemos el numero de archivos identificados por los antivirus como malware

    # obtenemos el resultado, si es detectado por 1 antivirus se considera malware
    $resultado = $positivo ? "" : " no";
    # escribimos en bitacora
    write_log($tipo, "Archivo '$file' enviado a Virustoral. Resultado: $positivo/$total => El archivo$resultado fue detectado como malware");
}

# crea un hash con los archivos en el directorio, el directorio es la llave
# Recibe:
#   @dirs -> lista de directorios
# Reorna:
#   %dir_info -> hash con los archivos encontrados en el directorio
sub get_files_in_dir{
    my @dirs = @_;
    #print "@dirs\n";
    my %dir_info;
    foreach $dir(@dirs){
        push @{$dir_info{"$dir"}}, get_files($dir); # obtenemos los archivos del directorio especificado y se agregan a un arreglo
    }
    return %dir_info;
}
#ciberarc

# genera un arreglo con lor archivos encontrados en un directorio
# Recibe:
#   $dir -> directorio en el que busca archivos
# Retorna:
#   @salida -> arreglo con los archivos encontrados
sub get_files{
    my $dir = shift(@_);
    my @salida;
    # abrimos el directorio
    opendir my $open_dir, "$dir" or die "No se puede abrir el directorio: $!";
    my @files = readdir $open_dir; # obtenemos los archivos del directorio
    closedir $open_dir; # cerramos el archivo

    foreach my $file(@files){
        if($file =~ /exe|vbs|py|cs|ps1|bat/){ # validamos que sean archivos que se pueden considerar maliciosos
            push @salida, $file; # agreamos el archivo al arreglo de salida
        }
    }
    return @salida; 
}

# procesa las direcciones que se especifican en el archivo de configuracion
# Recibe:
#   @dirs -> arreglo con los directorios en el archivo de configuracion
# Retorna:
#   @paths -> directorios procesados
sub get_path_dirs{
    my @dirs = @_;
    my @paths;
    # recorremos los directorios
    foreach $dir(@dirs){
        # validamos si tiene variables de entorno el directorio
        if ($dir =~ /\%(.*)\%/){ 
            $dir =~ m/(\%\w\%)/; # obtenemo la variable de entorno
            $environment = $1; # almacenamos el valor en una variable
            $dir =~ s/\%(.*)\%/$ENV{"$environment"}/g; # remplazamos la variable por su valor
        }
        push @paths, $dir; # agregamos el directirio al arreglo
    }
    return @paths;
}

# procesa las direcciones que se especifican en el archivo de configuracion
# Recibe:
#   $tipo -> tipo de elemento en el archivo de configuracion
#   $flag -> valor en el archivo de configuracion para consultar virustotal
#   %hash_dirs -> hash con las direcciones que se van a monitorear
sub check_dirs{
    my $tipo = shift(@_);
    my $flag = shift(@_);
    my %hash_dirs = %{$_[0]};
    my $mensaje;
    
    # recorremos el hash
    foreach my $path(keys %hash_dirs){
        my @original_files = @{$hash_dirs{$path}}; # obtenemos los archivos que se obtienen al inicio de la ejecucion
        my @actual_files = get_files($path); # obtenemos los archivos que se contienen en el directorio en tiempo real
        my $hash;

        #print "$#actual_files >= $#original_files or $#actual_files <= $#original_files\n";
        # validamos si se creo o elimino un elemento
        if ($#actual_files > $#original_files or $#actual_files < $#original_files){
            #print "entra";
            # bloque cuando se crea un nuevo archivo
            if ($#actual_files >= $#original_files){
                my @diff = array_diff(@original_files, @actual_files); # obtenemos los archivos creados
                $mensaje = "Se crearon archivos sospechosos '$path' => '@diff'"; # mensaje que se escribe en bitacora
                write_log($tipo, $mensaje); # escribimos en bitacora
                push(@{$hash_dirs{"$path"}}, @diff); # actualizamos los archivos originales agregando los que se crearon

                # si esta activada la opcion de mandar la muestra a virustotal
                if ($flag){
                    # ciclo por si se genera mas de un archivo
                    foreach my $new(@diff){
                        $hash = digest_file_hex("$path\\$new", "MD5"); # obtenemos el md5 del archivo creado
                        send_virustotal($hash, $tipo, $new); # enviamos la muestra a virus total
                    }
                }
            } else {
                my @diff = array_diff(@actual_files, @original_files); # obtenemos los archivos que se eliminaron
                $mensaje = "Se borraron archivos '$path' => '@diff'"; # mensaje que se escribe en bitacora 
                write_log($tipo, $mensaje); # escribimos en bitacora

                # eliminamos del arreglo de archivos los archivos que se borraron
                foreach $element(@diff){
                    @{$hash_dirs{"$path"}} = grep {$_ ne $element} @{$hash_dirs{"$path"}};
                }
            }
        }
    }
}

# funcion que escribe las salidas en la bitacora
# Recibe: 
#   $tipo -> FILE, DIRECTORIOS, ASEPS[rutas], etc.
#   $mensaje -> mensaje a mostrar en el archivo bitacora
sub write_log{
    my ($tipo, $mensaje) = @_; # obtenemos
    my $path = ".\\logs";

    #print "$tipo";
    mkdir $path unless -d $path; # se crea el archivo en caso de no existir
    my $file_out = "$path\\$log_file.log"; # nombre del archivo
    my $timestamp = get_time(); # obtenemos el tiempo actual
    open OUT, ">>", "$file_out" or die $!; # abrimos el archivo para que se escriba
    
    print OUT "[ $timestamp ] - $tipo: $mensaje.\n"; # escribimos en bitacora

    close OUT; # cerramos el archivo
}

# obtenemos el timestamp en un formato legible
# Retorna:
#   $nice_timestamp -> formato de la hora en manera legible
sub get_time{
    my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst)=localtime(time);
    my $nice_timestamp = sprintf ("%04d-%02d-%02d %02d:%02d:%02d",$year+1900,$mon+1,$mday,$hour,$min,$sec);
    return $nice_timestamp;
}

sub process_monitor(){
    my ($v1, $v2) = @_;
    my %list = $P->GetProcesses();

    ProcNums();
    foreach my $key ( keys %list ) 
    {
        my $process = substr $list{$key}, 0, -4; #print $process."\n";
        #$statsQuery="select * from Win32_PerfRawData_PerfProc_Process where IDProcess=".$$; #Usando PID
        $statsQuery="select * from Win32_PerfRawData_PerfProc_Process where Name='".$process."'"; #Nombres de proceso sin .exe #print $statsQuery;
        
        GetProcessInfo($v1,$v2,$key);
        #print $flag;
        #return $flag;
        #if ($flag){
        #    write_log("IOC", "Se detecto proceso '$process' con actividad inusual con uso de CPU mayor a $v2%");
        #}
    }
    #return $flag;
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
    my $PID = shift;          #PID del proceso
    my $processingTime=0;
    my $timeStamp=0;
    my $cpu=0;
    my $cpumin=0;
    my $ram=0;
    my $rammin=0;
    my $procName;
    my $path = "Procesos";
    mkdir $path unless -d $path;
    my $outfile = "$path\\Proceso_".$PID.".txt";

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
            $rammin = $procData->{WorkingSetPrivate};
        }
        #Se guarda el valor máximo en CPU (para detectar el minero) de las rondas
        if ($cpumin > $cpu){
            $cpu = $cpumin;
        }
        #Se guarda el valor máximo en RAM (para detectar el minero) de las rondas
        if ($rammin > $ram){
            $ram = $rammin;
        }
        #Se pasa a la sig ronda
        $limit -= 1;
    }
    # Se revisa si ha superado la tolerancia establecida
    if ($cpu > $tolerancia){
        $flag = 1;
        $ram = $ram/1000000;
        #print "Nombre de proceso :".$procName.", PID: $PID, MaxCPU:".sprintf("%.4f",$cpu)."%, RAM:".$ram."MB \n";
        #Mensaje a escribir
        write_log("IOC", "Se detecto proceso '$procName' con actividad inusual con uso de CPU al " . sprintf("%.2f", $cpu) ." %");
        `..\\..\\strings2\\x64\\Release\\strings.exe -pid $PID > $outfile` #Como puede ser una operación tardada, se hace solo con los que superar la funcionalidad
    }else{
        $flag = 0;
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

sub ram_analizer(){
    my $path = "IPs";
    mkdir $path unless -d $path;
    my $formato ="Procesos\\Proceso_*.txt";
    my @ls = glob($formato);
    my %urls;
    my $file;
    foreach $file (@ls) {
        if (-f $file){
            # Obtenemos los sitios visitados
            my $ip = "";
            print "Analizando $file...\n";
            # Abrimos el archivo para lectura
            open(FILE, $file) or die "No se pudo abrir $file: $!";
            #Obtenemos los strings que tengan htt
            while (<FILE>) {
                if (/\bhttp.*\b/i){
                    my $line = $_;
                    # Ya sacamos linea con http o https
                    $_ =~ s/ />/;
                    $_ =~ s/"/>/;
                    $_ =~ s/,/>/;
                    my $url = (split />/, $_)[0];       # Acá ya tenemos http?://pagina
                    #print $url;
                    #Revisamos si hay una newline
                    $ip = Nslookup($url);
                    # Conteo
                    my $rep = 1;
                    # Si existe e el hash, incrementamos la repetición
                    #print "$ip\n\n";
                    if ($ip){
                        #print "$ip";
                        if((exists $urls{$ip})){
                            $urls{$ip} += 1;
                        }else{
                            # Si no existe, se añade al hash $url{$repeticiones}
                            $urls{$ip} = $rep;
                        }
                    }
                }
            }
        }
        my $json = encode_json \%urls;
        #print "$file";
        my @outfile = split(/\\/, $file);
        $outfile[1] =~ s/txt/json/g;
        open OUTFILE, "> IPs\\IPs_$outfile[1]" or die $!;
        print OUTFILE $json;
        #sleep(0.25);
        close OUTFILE;
    }
}

sub Nslookup(){
    my $full = shift;
    #print $full;
    # Obtenemos solo el dominio
    my @tmp = split('//', $full);
    if (defined $tmp[1])
    {
        my @cast = split('/', $tmp[1]);
        if (defined $cast[0]){
            my $url = $cast[0];
            #print $url;
            my @nslookup = split '\n', `nslookup $url 2> nul`; #Obtiene las líneas de salida del comando netstat
            foreach (@nslookup) {
                if($_ =~ /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/){
                    return $1;
                } elsif ($_ =~ /^([0-9a-fA-F]{4}|0)(\:([0-9a-fA-F]{4}|0)){7}$/) {
                    return $1;
                }
            }
        }
    }else{
        return 0;
    }
}

sub network_monitor(){
    my $inpath = "IPS";
    my @ls = get_json_files($inpath);
    foreach my $file (@ls) {
        if ( $file =~ /\.json$/ ){
            my $json_text = do { open my $fh, '<', $file; local $/; <$fh> }; #Obtiene el contenido del json
            my $text = decode_json($json_text); # Decodificamos el contenido
            my @netstat = split '\n', `netstat -nat`; #Obtiene las líneas de salida del comando netstat
            shift @netstat for 1..6;
            foreach (@netstat) {
                my ($proto, $srcIPfull, $dstIPfull, $state, $dwnload) = split( ' ', $_ );
                my ($srcIP,$srcPort) = IPfilter($srcIPfull);
                my ($dstIP,$dstPort) = IPfilter($dstIPfull);
                if ($proto eq "TCP"){
                    print "Proto:$proto\n","IP Origen:$srcIP\n", "Pto. Origen:$srcPort\n","IP Destino:$dstIP\n","Pto. Destino:$dstPort\n", "STATE:$state\n", "DWN:$dwnload\n";       
                    #Obtenemos las claves del hash
                    foreach my $key (keys %{$text}){
                        if ($key eq $srcIP or $key eq $dstIP){
                            print "Coincidencia!!!!!!";
                        }
                    }
                }
                else{
                    print "Proto:$proto\n","IP Origen:$srcIP\n", "Pto. Origen:$srcPort\n","IP Destino:$dstIP\n","Pto. Destino:$dstPort\n";
                    foreach my $key (keys %{$text}){
                        if ($key eq $srcIP or $key eq $dstIP){
                            print "Coincidencia!!!!!!";
                        }
                    }
                }
            }
        }
    }    
}

sub get_json_files{
    my $dir = shift(@_);
    my @salida;
    # abrimos el directorio
    opendir my $open_dir, "$dir" or die "No se puede abrir el directorio: $!";
    my @files = readdir $open_dir; # obtenemos los archivos del directorio
    closedir $open_dir; # cerramos el archivo

    foreach my $file(@files){
        if($file =~ /json/){ # validamos que sean archivos que se pueden considerar maliciosos
            push @salida, $file; # agreamos el archivo al arreglo de salida
        }
    }
    return @salida; 
}

sub IPfilter(){
    my $fullIP = shift;
    if ($fullIP =~ /\*:\*\z/) {
        my ($IPfiltered,$port) = ("*","*");
        return ($IPfiltered,$port);
    }
    elsif (index($fullIP, '[') != -1) {
        #print "$srcIPfull es IPv6\n";    
        my @IP = split ']', $fullIP;
        #print scalar @IP,"\n";
        #Se quita el primer char para Port (:)
        my $port = pop @IP;
        #print "$port\n";
        my $tmp = reverse($port);chop($tmp);$port = reverse($tmp);
        #Si está vació el puerto
        if (not defined $port)
        {
            $port = "*";
        }
        #print "$port\n";
        #Se quita el primer char para IP ([)
        my $IPfiltered = pop @IP;
        #print "$IPfiltered\n";
        $tmp = reverse($IPfiltered);chop($tmp);$IPfiltered = reverse($tmp);
        #Si está vacia la IP
        if (not defined $IPfiltered)
        {
            $IPfiltered = "*";
        }
        #print "$IPfiltered\n";
        #Sustituimos '%' por '/' (para las máscaras)
        $IPfiltered =~ s/%/\//;
        return ($IPfiltered,$port);
    }
    else{
        my @IP = split ':', $fullIP;
        my ($IPfiltered, $port) = ($IP[1],$IP[2]);
        if (not defined $IPfiltered)
        {
            $IPfiltered = "*";
        }
        if (not defined $port)
        {
            $port = "*";
        }
        #Sustituimos '%' por '/' (para las máscaras)
        $IPfiltered =~ s/%/\//;
        return ($IPfiltered,$port);
    }
}

sub windows_security {
    my $firewall = shift(@_);
    my $defender = shift(@_);
    my $check_windows_firewall = shift(@_);
    my $check_windows_defender = shift(@_);

	if ($firewall) {
		#print "Revisando el firewall: ";
		my $fw_output = check_windows_security("$check_windows_firewall");
		#print $fw_output; # 0 o 6
        if ($fw_output){
            write_log("IOCS[WindowsSecurity]", "El firewall se ha desactivado");
        }
	}

	if ($defender) {
		#print "Revisando el Windows Defender: ";
		my $wd_output = check_windows_security("$check_windows_defender");
		#print $wd_output;
        unless ($wd_output){ # 0 o 4
            write_log("IOCS[WindowsSecurity]", "Windows Defender se ha desactivado");
        }
	}
}

# @arg script_block to execute
sub check_windows_security {
	my $ps= Win32::PowerShell::IPC->new();
	my $output= $ps->run_command("$_[0]");
}

=pod
sub task_schedule {
	# Corroboramos si existe la tarea programada
    my $powershell = shift(@_);
    #print "$powershell\n";
	my $output = exists_scheduledTask("$powershell");
	if ($output =~ /1/){
		#print "Existe: $output";
        write_log("ASEP[TAREAS]", "Existe la tarea programada 'tarea 1'");
	} #else {
		#print "No existe: $output";
	#}
}

sub exists_scheduledTask {
    my $var = shift(@_);
    #print "$var";
	my $ps= Win32::PowerShell::IPC->new();
	my $output= $ps->run_command("$var");
	return $output;
}
=cut


# Ejecucion del main
main();
