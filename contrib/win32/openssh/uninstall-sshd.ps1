if (!([bool]([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")))
{
    throw "You must be running as an administrator, please restart as administrator"
}

$scriptpath = $MyInvocation.MyCommand.Path
$scriptdir = Split-Path $scriptpath
$etwman = Join-Path $scriptdir "openssh-events.man"

if (Get-Service sshd -ErrorAction SilentlyContinue) 
{
   Stop-Service sshd
   sc.exe delete sshd 1>$null
   Write-Host -ForegroundColor Green "sshd successfully uninstalled"
}
else {
    Write-Host -ForegroundColor Yellow "sshd service is not installed"
}

# unregister etw provider
wevtutil um `"$etwman`"

if (Get-Service ssh-agent -ErrorAction SilentlyContinue) 
{
   Stop-Service ssh-agent
   sc.exe delete ssh-agent 1>$null
   Write-Host -ForegroundColor Green "ssh-agent successfully uninstalled"
}
else {
    Write-Host -ForegroundColor Yellow "ssh-agent service is not installed"
}
