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
		echo "Firewall apagado";
	} 
	elseif ($method -eq "1"){
		echo "Firewall prendido";
	} else {
		echo "Error";
	}
}

check_reg_value "LocalMachine" $reg_fw_key1 "EnableFirewall"
check_reg_value "LocalMachine" $reg_fw_key2 "EnableFirewall"
check_reg_value "LocalMachine" $reg_fw_key3 "EnableFirewall"
check_reg_value "LocalMachine" $reg_fw_key4 "EnableFirewall"
check_reg_value "LocalMachine" $reg_fw_key5 "EnableFirewall"
check_reg_value "LocalMachine" $reg_fw_key6 "EnableFirewall"