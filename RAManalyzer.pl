#Para el análisis de los archivos obtenidos del volcado de memoria:
#Formato de los archivo "Proceso_PID.txt"
use strict;
use warnings;
use Data::Dumper;
use JSON;

sub main(){
    my $formato ="Proceso_*.txt";
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
                if (/\bhttp*\b/i){
                    my $line = $_;
                    if (index($line, "http://") != -1){
                        my $tmp = (split /http:/, $line, 2)[1];
                        # Limpiamos más las URLs (quitamos lo que esté después de ", > y ,)
                        $tmp =~ s/ />/;
                        $tmp =~ s/"/>/;
                        $tmp =~ s/,/>/;
                        my $url = (split />/, $tmp)[0];

                        #Revisamos si hay una newline
                        if ($url eq "\n"){
                            last;
                        }else{
                            $url = "http:".$url;
                            #print "$url\n";
                            # Como necesitamos resolver el nombre de dominio, se hace nslookup a las urls:
                            $ip = Nslookup($url);
                        }
                        
                        my $rep = 1;
                        # Si existe e el hash, incrementamos la repetición
                        if((exists $urls{$ip})){
                            $rep = $urls{$ip};
                            $rep += 1;
                            $urls{$ip} = $rep;
                        }else{
                            # Si no existe, se añade al hash $url{$repeticiones}
                            $urls{$ip} = $rep;
                        }
                    }elsif (index($line, "https://") != -1){
                        my $tmp = (split /https:/, $line, 2)[1];
                        # Limpiamos más las URLs (quitamos lo que esté después de ", > y ,)
                        $tmp =~ s/ />/;
                        $tmp =~ s/"/>/;
                        $tmp =~ s/,/>/;
                        my $url = (split />/, $tmp)[0];
                        #Revisamos si hay una newline
                        if ($url eq "\n"){
                            last;
                        }else{
                            $url = "https:".$url;
                            #print "$url\n";
                            # Como necesitamos resolver el nombre de dominio, se hace nslookup a las urls:
                            $ip = Nslookup($url);
                        }
                        
                        my $rep = 1;
                        # Si existe e el hash, incrementamos la repetición
                        if((exists $urls{$ip})){
                            $rep = $urls{$ip};
                            $rep += 1;
                            $urls{$ip} = $rep;
                        }else{
                            # Si no existe, se añade al hash $url{$repeticiones}
                            $urls{$ip} = $rep;
                        }
                    }
                };
            }
        }
        my $json = encode_json \%urls;
        open OUTFILE, "> IPs_$file" or die $1;
        print OUTFILE $json;
        close OUTFILE;
    }
}

sub Nslookup(){
    my ($full) = @_;
    # Obtenemos solo el dominio
    my @tmp = split('//', $full);
    if ($tmp[1] eq "")
    {
        last;
    }
    my $dom = $tmp[1];
    @tmp = split('/', $dom);
    my $url = $tmp[0];
    #print $url,$tmp[0],$dom,$full;
    my @nslookup = split '\n', `nslookup $url > nul`; #Obtiene las líneas de salida del comando netstat
    foreach (@nslookup) {
        if($_ =~ /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/)
        {
            return $1;
        }
    }
}

main();