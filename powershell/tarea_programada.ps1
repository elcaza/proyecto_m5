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
exists_scheduledTask