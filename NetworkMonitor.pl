use strict;
use warnings;

# Revisar conexiones del equipo (TCPviewer)
sub main(){
    my @netstat = split '\n', `netstat -nat`; #Obtiene las líneas de salida del comando netstat
    shift @netstat for 1..6;
    foreach (@netstat) {
        my ($proto, $srcIPfull, $dstIPfull, $state, $dwnload) = split( ' ', $_ );
        my ($srcIP,$srcPort) = IPfilter($srcIPfull);
        my ($dstIP,$dstPort) = IPfilter($dstIPfull);
        if ($proto eq "TCP"){
            print "Proto:$proto\n","IP Origen:$srcIP\n", "Pto. Origen:$srcPort\n","IP Destino:$dstIP\n","Pto. Destino:$dstPort\n", "STATE:$state\n", "DWN:$dwnload\n";
        }
        else{
            print "Proto:$proto\n","IP Origen:$srcIP\n", "Pto. Origen:$srcPort\n","IP Destino:$dstIP\n","Pto. Destino:$dstPort\n";
        }
    }
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
        print scalar @IP,"\n";
        #Se quita el primer char para Port (:)
        my $port = pop @IP;
        print "$port\n";
        my $tmp = reverse($port);chop($tmp);$port = reverse($tmp);
        print "$port\n";
        #Se quita el primer char para IP ([)
        my $IPfiltered = pop @IP;
        print "$IPfiltered\n";
        $tmp = reverse($IPfiltered);chop($tmp);$IPfiltered = reverse($tmp);
        print "$IPfiltered\n";
        #Sustituimos '%' por '/' (para las máscaras)
        $IPfiltered =~ s/%/\//;
        return ($IPfiltered,$port);
    }
    else{
        my @IP = split ':', $fullIP;
        my ($IPfiltered, $port) = ($IP[1],$IP[2]);
        #Sustituimos '%' por '/' (para las máscaras)
        $IPfiltered =~ s/%/\//;
        return ($IPfiltered,$port);
    }
}

main();