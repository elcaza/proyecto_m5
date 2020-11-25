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