# https://blog.netwrix.com/2018/09/11/how-to-get-edit-create-and-delete-registry-keys-with-powershell/

#perl2exe_include "C:\Strawberry\cpan\build\Win32-PowerShell-IPC-0.02-0\lib\Win32\PowerShell\IPC.pm"
use strict;
use warnings;

# Modulo que permite saber si el firewall está desactivado
################################################################
# Inicia Variables


my $powershell_scheduledTask = '
$reg_fw_key1 = "SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile";
$reg_fw_key2 = "SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile";
$reg_fw_key3 = "SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile";
$reg_fw_key4 = "SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile";
$reg_fw_key5 = "SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile";
$reg_fw_key6 = "SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile";

[Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey("LocalMachine",$env:COMPUTERNAME).OpenSubKey("$reg_fw_key1").GetValue("EnableFirewall");
[Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey("LocalMachine",$env:COMPUTERNAME).OpenSubKey("$reg_fw_key2").GetValue("EnableFirewall");
[Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey("LocalMachine",$env:COMPUTERNAME).OpenSubKey("$reg_fw_key3").GetValue("EnableFirewall");
[Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey("LocalMachine",$env:COMPUTERNAME).OpenSubKey("$reg_fw_key4").GetValue("EnableFirewall");
[Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey("LocalMachine",$env:COMPUTERNAME).OpenSubKey("$reg_fw_key5").GetValue("EnableFirewall");
[Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey("LocalMachine",$env:COMPUTERNAME).OpenSubKey("$reg_fw_key6").GetValue("EnableFirewall");';

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