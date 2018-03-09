# @manojampalam - authored initial script
# @friism - Fixed issue with invalid SDDL on Set-Acl
# @manojampalam - removed ntrights.exe dependency
# @bingbing8 - removed secedit.exe dependency

$scriptpath = $MyInvocation.MyCommand.Path
$scriptdir = Split-Path $scriptpath

$sshdpath = Join-Path $scriptdir "sshd.exe"
$sshagentpath = Join-Path $scriptdir "ssh-agent.exe"
$etwman = Join-Path $scriptdir "openssh-events.man"

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

# unregister etw provider
wevtutil um `"$etwman`"

# adjust provider resource path in instrumentation manifest
[XML]$xml = Get-Content $etwman
$xml.instrumentationManifest.instrumentation.events.provider.resourceFileName = $sshagentpath.ToString()
$xml.instrumentationManifest.instrumentation.events.provider.messageFileName = $sshagentpath.ToString()
$xml.Save($etwman)

#register etw provider
wevtutil im `"$etwman`"

New-Service -Name ssh-agent -BinaryPathName `"$sshagentpath`" -Description "SSH Agent" -StartupType Manual | Out-Null
cmd.exe /c 'sc.exe sdset ssh-agent D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;RP;;;AU)'

New-Service -Name sshd -BinaryPathName `"$sshdpath`" -Description "SSH Daemon" -StartupType Manual | Out-Null

Write-Host -ForegroundColor Green "sshd and ssh-agent services successfully installed"
