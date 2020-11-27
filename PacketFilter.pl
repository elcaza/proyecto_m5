use Net::TcpDumpLog;
use NetPacket::Ethernet;
use NetPacket::IP;
use NetPacket::TCP;

use strict;
use warnings;

sub main()
{
    while ("1"){
        my $bad_files = "0";

        #Corremos Wireshark y esperamos 1 min 
        #my $wirecmd = 'algo'
        #`powershell.exe -windowstyle hidden -command $wirecmd`
        
        # Accedemos al archivo que guarda y volcamos la info
        my $file = "Test.pcap";
        my $log = Net::TcpDumpLog->new();
        $log->read($file);

        foreach my $index ($log->indexes) { 
            my ($length_orig, $length_incl, $drops, $secs, $msecs) = $log->header($index); 
            my $data = $log->data($index);
            
            my $eth_obj = NetPacket::Ethernet->decode($data);    
            next unless $eth_obj->{type} == NetPacket::Ethernet::ETH_TYPE_IP;

            my $ip_obj = NetPacket::IP->decode($eth_obj->{data});
            next unless $ip_obj->{proto} == NetPacket::IP::IP_PROTO_TCP;

            my $tcp_obj = NetPacket::TCP->decode($ip_obj->{data});
            my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime($secs + $msecs/1000);

            my $tcp_data = NetPacket::TCP::strip($eth_obj->{data});
            
            if ($tcp_data =~ /[A-Za-z0_9][A-Za-z0-9_\-\.]+\.exe|[A-Za-z0_9][A-Za-z0-9_\-\.]+\.vbs|[A-Za-z0_9][A-Za-z0-9_\-\.]+\.py|[A-Za-z0_9][A-Za-z0-9_\-\.]+\.cs|[A-Za-z0_9][A-Za-z0-9_\-\.]+\.ps.|[A-Za-z0_9][A-Za-z0-9_\-\.]+\.bat|[A-Za-z0_9][A-Za-z0-9_\-\.]+\.msi|[A-Za-z0_9][A-Za-z0-9_\-\.]+\.cmd/){
                print sprintf("====%02d-%02d %02d:%02d:%02d.%d", 
                $mon, $mday, $hour, $min, $sec, $msecs), 
                " ", $eth_obj->{src_mac}, " -> ", 
                $eth_obj->{dest_mac}, "====";
                print "\t", $ip_obj->{src_ip}, ":", $tcp_obj->{src_port}, 
                " -> ", 
                $ip_obj->{dest_ip}, ":", $tcp_obj->{dest_port}, "====";
                print $tcp_data,"====";
                print $bad_files;
                $bad_files = "1";
            }
        }
        sleep(60)
    }
}
main()