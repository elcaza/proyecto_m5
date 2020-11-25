#Para el análisis de los archivos obtenidos del volcado de memoria:
#Formato de los archivo "Proceso_PID.txt"
use strict;
use warnings;
use Data::Dumper;

sub main(){
    my $formato ="Proceso_*.txt";
    my @ls = glob($formato);
    my %urls;
    my $file;
    foreach $file (@ls) {
        if (-f $file){
            # Obtenemos los sitios visitados
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
                            Nslookup($url);
                        }
                        
                        my $rep = 1;
                        # Si existe e el hash, incrementamos la repetición
                        if((exists $urls{$url})){
                            $rep = $urls{$url};
                            $rep += 1;
                            $urls{$url} = $rep;
                        }else{
                            # Si no existe, se añade al hash $url{$repeticiones}
                            $urls{$url} = $rep;
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
                            Nslookup($url);
                        }
                        
                        my $rep = 1;
                        # Si existe e el hash, incrementamos la repetición
                        if((exists $urls{$url})){
                            $rep = $urls{$url};
                            $rep += 1;
                            $urls{$url} = $rep;
                        }else{
                            # Si no existe, se añade al hash $url{$repeticiones}
                            $urls{$url} = $rep;
                        }
                    }
                };
            }
        }
        open OUTFILE, "> IPs_$file" or die $1;
        print OUTFILE Dumper(\%urls);
        close OUTFILE;
    }
}

sub Nslookup(){
    my $full = shift;
    # Obtenemos solo el dominio
    my @tmp = split('//', $full);
    my $dom = $tmp[1];
    @tmp = split('/', $dom);
    my $url = $tmp[0];
    print $url;
    my @nslookup = split '\n', `nslookup $url`; #Obtiene las líneas de salida del comando netstat
    foreach (@nslookup) {
        print $_;
    }
}

main();