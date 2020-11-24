use strict;
use warnings;
use Win32::OLE('in');
use Win32::Process::List;
use Parse::Netstat qw(parse_netstat);

#Variables globales
my $processorCount;
my $statsQuery;
my $objWMIService = Win32::OLE->GetObject("winmgmts://./root/cimv2") or die "WMI connection failed.n";
my $P = Win32::Process::List->new();
my $res = parse_netstat(output=>join("", `netstat -anp`), flavor=>"win32");

sub main()
{
 my %list = $P->GetProcesses();
 foreach my $key ( keys %list ) {
      my $process = substr $list{$key}, 0, -4;
      #print $process."\n";
      #$statsQuery="select * from Win32_PerfRawData_PerfProc_Process where IDProcess=".$$; #Usando PID
      $statsQuery="select * from Win32_PerfRawData_PerfProc_Process where Name='".$process."'"; #Nombres de proceso sin .exe
      #print $statsQuery;
      GetProcessorCount();
      GetUtilizationStats();
 }
 NetstatWin();
}

sub NetstatWin()
{
    my $res = parse_netstat(output=>join("", `netstat -anp`), flavor=>"win32");
    print "$res\n";
}

sub GetProcessorCount()
{
 my $cols=$objWMIService->ExecQuery("select NumberOfLogicalProcessors from Win32_ComputerSystem");
 
 foreach my $v (in $cols) 
 { 
 $processorCount = $v->{NumberOfLogicalProcessors};
 }
}

sub GetUtilizationStats()
{
 my $processingTime=0;
 my $timeStamp=0;
 my $cpu=0;
 my $cpumin=0;
 my $ram=0;
 my $name;
 my $limit = 10;        #Cantidad de calculos que realiza por proceso
 my $tolerancia = 10;   #Porcentaje de CPU que levanta alerta
 while($limit != 0)
 {

    my $cols = $objWMIService->ExecQuery($statsQuery);

    foreach my $Data( in $cols){
    $name=$Data->{Name};
    $cpumin = GetCorrectCPUData($processingTime,$Data->{PercentProcessorTime},$timeStamp,$Data->{TimeStamp_Sys100NS});
    $processingTime=$Data->{PercentProcessorTime};
    $timeStamp=$Data->{TimeStamp_Sys100NS};
    $ram=$Data->{WorkingSetPrivate};
    }

 if ($cpumin > $cpu){
     $cpu = $cpumin;
 }
 $limit -= 1;
 }
 if ($cpu > 10){
 print "Name :".$name.", MAXCPU:".sprintf("%.2f",$cpu)."%, RAM:".$ram."\n"; #Mensaje a escribir
 }
}


sub GetCorrectCPUData()
{
 #CPU utilization calculation logic. 
 my $oldProcessingData = shift;
 my $newProcessingData = shift;
 my $oldProcessingTime = shift;
 my $newProcessingTime = shift;
 
 my $diffProcessingData = ($newProcessingData - $oldProcessingData);
 my $diffProcessingTime = ($newProcessingTime - $oldProcessingTime);
 
 my $utilization=(($diffProcessingData/$diffProcessingTime)*100)/$processorCount;
 
 return $utilization;
}

#Corre la función del monitoreo
main();