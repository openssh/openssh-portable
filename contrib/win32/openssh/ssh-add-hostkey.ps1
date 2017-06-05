<# 
 Author: manoj.ampalam@microsoft.com

 Description: ssh-add.exe like Powershell utility to do host key management.
 Input parameter mimic ssh-add.exe cmdline arguments. 
 
 Host keys on Windows need to be registered as SYSTEM (i.e ssh-add.exe would 
 need to run as SYSTEM while talking to ssh-agent). This typically requires 
 an external utility like psexec. 

 This script tries to use the Task scheduler option:
  - registers a task scheduler task to run ssh-add.exe operation as SYSTEM
  - actual output of ssh-add.exe is written to file (both stdout and stderr)
  - Dumps the file contents to console

#>

# see https://linux.die.net/man/1/ssh-add for what the arguments mean
Param(
  [switch]$List_fingerprints, #ssh-add -l 
  [switch]$List_pubkeys,      #ssh-add -L 
  [switch]$Delete_key,        #ssh-add -d 
  [switch]$Delete_all,        #ssh-add -D
  [string]$key="" 

)

$switch_count = 0
if ($List_fingerprints) {$switch_count++}
if ($List_pubkeys)      {$switch_count++}
if ($Delete_key)        {$switch_count++}
if ($Delete_all)        {$switch_count++}        

if ($switch_count -gt 1) {
    throw "Invalid usage: More than one operation specified"
}

#create ssh-add cmdlinet
$ssh_add_cmd = "ssh-add"
if ($switch_count -eq 0)    { $ssh_add_cmd += " $key"  }
elseif ($List_fingerprints) { $ssh_add_cmd += " -l" } 
elseif ($List_pubkeys)      { $ssh_add_cmd += " -L" } 
elseif ($Delete_key)        { $ssh_add_cmd += " -d $key" } 
elseif ($Delete_all)        { $ssh_add_cmd += " -D" } 

#globals
$taskfolder = "\OpenSSHUtils\hostkey_tasks\"
$taskname = "hostkey_task"
$ssh_add_output = Join-Path (pwd).Path "ssh-add-hostkey-tmp.txt"
$task_argument = "/c `"$ssh_add_cmd > $ssh_add_output 2>&1`""

#create TaskScheduler task
$ac = New-ScheduledTaskAction -Execute "cmd.exe" -Argument $task_argument -WorkingDirectory (pwd).path
$task = Register-ScheduledTask -TaskName $taskname -User System -Action $ac -TaskPath $taskfolder -Force

#run the task
if (Test-Path $ssh_add_output) {Remove-Item $ssh_add_output -Force}
Start-ScheduledTask -TaskPath $taskfolder -TaskName $taskname

#wait a little while for task to complete
Sleep 1
if (-not(Test-Path $ssh_add_output)) {throw "cannot find task output file. Something went WRONG!!! "}

#dump output to console
Get-Content $ssh_add_output

#cleanup task and output file
Remove-Item $ssh_add_output -Force
Unregister-ScheduledTask -TaskPath $taskfolder -TaskName $taskname -Confirm:$false




