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

$ioc_fw = $reg_key1 + $reg_key2 + $reg_key3 + $reg_key4
echo $ioc_fw;