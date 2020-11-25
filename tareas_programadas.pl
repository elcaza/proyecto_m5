#perl2exe_include "C:\Strawberry\cpan\build\Win32-PowerShell-IPC-0.02-0\lib\Win32\PowerShell\IPC.pm"
use strict;
use warnings;
use lib 'C:\\Strawberry\\cpan\\build\\Win32-PowerShell-IPC-0.02-0\\lib\Win32\PowerShell\\';
use Win32::PowerShell::IPC; # cpan Win32::PowerShell::IPC

# Modulo que permite saber si hay una tarea programada
# mediante Taskname o TaskPath

################################################################
# Inicia Variables

# Para filtrar por taskname
# my $process_name = "OobeDiscovery";
# my $method = "TaskName";

# Para filtrar por taskpath
my $process_name = "\\Microsoft\\XblGameSave\\";
my $method = "TaskPath";

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


################################################################
# Inicio

print("Iniciando programa...\n");
#my $var = execute_powershell_cmd("ls");
#print $var;
main();
print("End\n");

################################################################
# Función principal
sub main {
	my $output = &exists_scheduledTask("$powershell_scheduledTask");
	if ($output == 1){
		print "Existe: $output";
	} else {
		print "No existe: $output";
	}
}


################################################################
# Inicia funciones

# @arg command to execute
sub execute_powershell_cmd {
	my $cmd = $_[0];
	my $result = `powershell -c $cmd`;
}

# @arg script_block to execute
sub exists_scheduledTask {
	my $ps= Win32::PowerShell::IPC->new();
	my $output= $ps->run_command("$_[0]");
	return $output;
}