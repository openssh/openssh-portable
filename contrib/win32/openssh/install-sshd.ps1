# @manojampalam - authored initial script
# @friism - Fixed issue with invalid SDDL on Set-Acl
# @manojampalam - removed ntrights.exe dependency

$scriptpath = $MyInvocation.MyCommand.Path
$scriptdir = Split-Path $scriptpath

$sshdpath = Join-Path $scriptdir "sshd.exe"
$sshagentpath = Join-Path $scriptdir "ssh-agent.exe"
$logsdir = Join-Path $scriptdir "logs"

$sshdAccount = "NT SERVICE\SSHD"

if (-not (Test-Path $sshdpath)) {
    throw "sshd.exe is not present in script path"
}

if (Get-Service sshd -ErrorAction SilentlyContinue) 
{
   Stop-Service sshd
   sc.exe delete sshd 1> null
}

if (Get-Service ssh-agent -ErrorAction SilentlyContinue) 
{
   Stop-Service ssh-agent
   sc.exe delete ssh-agent 1> null
}

New-Service -Name ssh-agent -BinaryPathName $sshagentpath -Description "SSH Agent" -StartupType Manual | Out-Null
cmd.exe /c 'sc.exe sdset ssh-agent D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;RP;;;AU)'

New-Service -Name sshd -BinaryPathName $sshdpath -Description "SSH Daemon" -StartupType Manual -DependsOn ssh-agent | Out-Null
sc.exe config sshd obj= "NT AUTHORITY\NetworkService"
sc.exe sidtype sshd unrestricted

if(-not (test-path $logsdir -PathType Container))
{
    $null = New-Item $logsdir -ItemType Directory -Force -ErrorAction Stop
}
$rights = [System.Security.AccessControl.FileSystemRights]"Read, Write"
$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($sshdAccount, $rights, "ContainerInherit,ObjectInherit", "None", "Allow")
$acl = Get-Acl -Path $logsdir
$Acl.SetAccessRule($accessRule)
Set-Acl -Path $logsdir -AclObject $acl
Write-Host -ForegroundColor Green "sshd and ssh-agent services successfully installed"
