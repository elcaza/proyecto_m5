use strict;
use warnings;
use lib 'C:\\Strawberry\\cpan\\build\\Win32-PowerShell-IPC-0.02-0\\lib\Win32\PowerShell\\';
use Win32::PowerShell::IPC; # cpan Win32::PowerShell::IPC

# Modulo que alerta si se apaga el firewall o windows defender
# mediante "WindowsSecurity" del archivo de configuración

################################################################
# Inicia Variables

my $check_firewall = 1; # Debe provenir del archivo config
my $check_defender = 1; # Debe provenir del archivo config

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
	elseif ($value -eq "1"){
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

# 0 - 6
# 0 => totalmente apagado [Not ok]
# 6 => totalmente prendido [Ok]
$ioc_fw = $reg_key1 + $reg_key2 + $reg_key3 + $reg_key4 +$reg_key5 + $reg_key6;
echo $ioc_fw;
';

my $check_windows_defender = '
# original
# [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey("LocalMachine",$env:COMPUTERNAME).OpenSubKey("System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile").GetValue("EnableFirewall")

# Prueba unitaria
# [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey("LocalMachine",$env:COMPUTERNAME).OpenSubKey("SOFTWARE\Microsoft\Windows Defender\Features").GetValue("TamperProtection")

# Valor activado
# Valor desactivado

# HKLM\SOFTWARE\Microsoft\Windows Defender\Features\TamperProtection: 0x00000001
# HKLM\SOFTWARE\Microsoft\Windows Defender\Features\TamperProtection: 0x00000004
$normal_TamperProtection = 1;

# HKLM\SOFTWARE\Microsoft\Windows Defender\Features\TamperProtectionSource: 0x00000005
# HKLM\SOFTWARE\Microsoft\Windows Defender\Features\TamperProtectionSource: 0x00000002
$normal_TamperProtectionSource = 5;

# HKLM\SOFTWARE\Microsoft\Windows Defender\Spynet\SpyNetReporting: 0x00000002
# HKLM\SOFTWARE\Microsoft\Windows Defender\Spynet\SpyNetReporting: 0x00000000
$normal_SpyNetReporting = 2;

# HKLM\SOFTWARE\Microsoft\Windows Defender\Spynet\SubmitSamplesConsent: 0x00000001
# HKLM\SOFTWARE\Microsoft\Windows Defender\Spynet\SubmitSamplesConsent: 0x00000000
$noraml_SubmitSamplesConsent = 1;

$reg_wd_key1 = "SOFTWARE\Microsoft\Windows Defender\Features";
$reg_wd_key2 = "SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile";
$reg_wd_key3 = "SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile";
$reg_wd_key4 = "SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile";

function check_reg_value {
	param (
		$base_key,
		$reg_key,
		$reg_value,
		$normal_value
	)

	$value = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey("$base_key",$env:COMPUTERNAME).OpenSubKey("$reg_key").GetValue("$reg_value");

	if ($value -ne $normal_value){
		# echo "Protección apagada";
		return 0;
	} 
	else {
		# echo "Protección prendida";
		return 1;
	} 
}

$reg_key1 = check_reg_value "LocalMachine" $reg_wd_key1 "TamperProtection" $normal_TamperProtection;
$reg_key2 = check_reg_value "LocalMachine" $reg_wd_key2 "TamperProtectionSource" $normal_TamperProtectionSource;
$reg_key3 = check_reg_value "LocalMachine" $reg_wd_key3 "SpyNetReporting" $normal_SpyNetReporting;
$reg_key4 = check_reg_value "LocalMachine" $reg_wd_key4 "SubmitSamplesConsent" $noraml_SubmitSamplesConsent;

# 0 - 4
# 0 => totalmente apagado [Not ok]
# 4 => totalmente prendido [Ok]
$ioc_fw = $reg_key1 + $reg_key2 + $reg_key3 + $reg_key4
echo $ioc_fw;
';

# my $pw_args = "$process_name $method\n";
# $powershell_scheduledTask = "$powershell_scheduledTask $pw_args";


################################################################
# Inicio

print("Iniciando programa...\n");
# my $var = execute_powershell_cmd("ls");
# print $var;
main();
print("End\n");

################################################################
# Función principal
sub main {
	if ($check_firewall == 1) {
		print "Revisando el firewall: ";
		my $fw_output = &check_windows_security("$check_windows_firewall");
		print $fw_output;
	}

	if ($check_defender == 1) {
		print "Revisando el Windows Defender: ";
		my $wd_output = &check_windows_security("$check_windows_defender");
		print $wd_output;
	}
}

################################################################
# Inicia funciones

# @arg script_block to execute
sub check_windows_security {
	my $ps= Win32::PowerShell::IPC->new();
	my $output= $ps->run_command("$_[0]");
}