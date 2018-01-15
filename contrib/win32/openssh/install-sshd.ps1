# @manojampalam - authored initial script
# @friism - Fixed issue with invalid SDDL on Set-Acl
# @manojampalam - removed ntrights.exe dependency
# @bingbing8 - removed secedit.exe dependency

$scriptpath = $MyInvocation.MyCommand.Path
$scriptdir = Split-Path $scriptpath

$sshdpath = Join-Path $scriptdir "sshd.exe"
$sshagentpath = Join-Path $scriptdir "ssh-agent.exe"
$logsdir = Join-Path $scriptdir "logs"

if (-not (Test-Path $sshdpath)) {
    throw "sshd.exe is not present in script path"
}

if (Get-Service sshd -ErrorAction SilentlyContinue) 
{
   Stop-Service sshd
   sc.exe delete sshd 1>$null
}

if (Get-Service ssh-agent -ErrorAction SilentlyContinue) 
{
   Stop-Service ssh-agent
   sc.exe delete ssh-agent 1>$null
}

New-Service -Name ssh-agent -BinaryPathName `"$sshagentpath`" -Description "SSH Agent" -StartupType Manual | Out-Null
cmd.exe /c 'sc.exe sdset ssh-agent D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;RP;;;AU)'

New-Service -Name sshd -BinaryPathName `"$sshdpath`" -Description "SSH Daemon" -StartupType Manual | Out-Null

# create sshd account with random password if it does not already exist
# New-LocalUser only exists on PS V5
# New-LocalUser -Name sshd -AccountNeverExpires -Password (ConvertTo-SecureString (new-guid).guid -AsPlainText -Force) -ErrorAction SilentlyContinue | Out-Null
# net user prompts if password is more than 14 chars long
net user sshd (new-guid).guid.substring(1,14) /add > $null 2>&1


# create logs folder and set its permissions
if(-not (test-path $logsdir -PathType Container))
{
    $null = New-Item $logsdir -ItemType Directory -Force -ErrorAction Stop
}
$acl = Get-Acl -Path $logsdir
# following SDDL implies 
# - owner - built in Administrators
# - disabled inheritance
# - Full access to System
# - Full access to built in Administrators
$acl.SetSecurityDescriptorSddlForm("O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
Set-Acl -Path $logsdir -AclObject $acl

Write-Host -ForegroundColor Green "sshd and ssh-agent services successfully installed"
