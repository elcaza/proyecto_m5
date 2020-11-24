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
       echo "Existe"; 
    } else {
       echo "No existe";
    }

    # Write-Output $name $method

}
exists_scheduledTask "OobeDiscovery" "TaskName"
exists_scheduledTask "\Microsoft\XblGameSave\" "TaskPath"