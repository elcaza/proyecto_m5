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

# archivo de bitacora
my $log_file = get_time();
$log_file =~ s/( |:)/_/g;

# archivo de configuracion
my $file = "config.json";
my $msg = "";

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
        my $flag = $text->{FLAG}; # obtenemos el valor de la bandera para consultar virus total

        # lista de hashes de los archivos especificados en el archivo de configuracion
        my %hash_files = get_hashes(@files_list);
        my %dirs = get_files_in_dir(get_path_dirs(@dir_list));
        my %rutas = get_files_in_dir(get_path_dirs(@{$aseps_hash{"rutas"}}));

        # ciclo infinito es el core del programa, aqui van todas las funciones que se van a estar
        # ejecutando
        while(1){
            check_files(\%hash_files);
            check_dirs("DIRECTORIOS", $flag, \%dirs);
            check_dirs("ASEPS[rutas]", $flag, \%rutas);
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


# Ejecucion del main
main();
