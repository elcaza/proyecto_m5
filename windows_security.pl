use strict;
use warnings;
use lib 'C:\\Strawberry\\cpan\\build\\Win32-PowerShell-IPC-0.02-0\\lib\Win32\PowerShell\\';
use Win32::PowerShell::IPC; # cpan Win32::PowerShell::IPC

# Modulo que alerta si se apaga el firewall o windows defender
# mediante "WindowsSecurity" del archivo de configuración

################################################################
# Inicia Variables

my $check_firewall = 1;
my $check_defender = 1;

# Finaliza Variables a configurar
################################################################

my $check_windows_firewall = '
# original
# [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey("LocalMachine",$env:COMPUTERNAME).OpenSubKey("System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile").GetValue("EnableFirewall")

$reg_fw_key1 = "SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile";
$reg_fw_key2 = "SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile";
$reg_fw_key3 = "SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile";
$reg_fw_key4 = "SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile";
$reg_fw_key5 = "SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile";
$reg_fw_key6 = "SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile";

function check_reg_value {
	param (
		$base_key,
		$reg_key,
		$reg_value
	)

	$value = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey("$base_key",$env:COMPUTERNAME).OpenSubKey("$reg_key").GetValue("$reg_value");

	if ($value -eq "0"){
		#echo "Firewall apagado";
		return 0;
	} 
	elseif ($method -eq "1"){
		#echo "Firewall prendido";
		return 1;
	} else {
		#echo "Error";
		return -10;
	}
}

$reg_key1 = check_reg_value "LocalMachine" $reg_fw_key1 "EnableFirewall"
$reg_key2 = check_reg_value "LocalMachine" $reg_fw_key2 "EnableFirewall"
$reg_key3 = check_reg_value "LocalMachine" $reg_fw_key3 "EnableFirewall"
$reg_key4 = check_reg_value "LocalMachine" $reg_fw_key4 "EnableFirewall"
$reg_key5 = check_reg_value "LocalMachine" $reg_fw_key5 "EnableFirewall"
$reg_key6 = check_reg_value "LocalMachine" $reg_fw_key6 "EnableFirewall"

$ioc_fw = $reg_key1 + $reg_key2 + $reg_key3 + $reg_key4 +$reg_key5 + $reg_key6;
echo $ioc_fw; ';

my $pw_args = "$process_name $method\n";
$powershell_scheduledTask = "$powershell_scheduledTask $pw_args";


################################################################
# Inicio

print("Iniciando programa...\n");
my $var = execute_powershell_cmd("ls");
print $var;
#main();
print("End\n");

################################################################
# Función principal
sub main {
	my $output = &exists_scheduledTask("$powershell_scheduledTask");
	print $output;
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
}