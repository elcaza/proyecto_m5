use strict;
use warnings;
use Data::Dumper;
use JSON::MaybeXS qw(encode_json decode_json);

# Revisar conexiones del equipo (TCPviewer)
sub main(){
    my $inpath = ".";
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

main();