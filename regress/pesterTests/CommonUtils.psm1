Import-Module OpenSSHUtils -Force

Add-Type -TypeDefinition @"
   public enum PlatformType
   {
      Windows,
      Linux,
      OSX
   }
"@

function Get-Platform {
    # Use the .NET Core APIs to determine the current platform; if a runtime
    # exception is thrown, we are on FullCLR, not .NET Core.
    try {
        $Runtime = [System.Runtime.InteropServices.RuntimeInformation]
        $OSPlatform = [System.Runtime.InteropServices.OSPlatform]
        
        $IsLinux = $Runtime::IsOSPlatform($OSPlatform::Linux)
        $IsOSX = $Runtime::IsOSPlatform($OSPlatform::OSX)
        $IsWindows = $Runtime::IsOSPlatform($OSPlatform::Windows)
    } catch {    
        try {            
            $IsLinux = $false
            $IsOSX = $false
            $IsWindows = $true
        }
        catch { }
    }
    if($IsOSX) {
        [PlatformType]::OSX
    } elseif($IsLinux) {
        [PlatformType]::Linux
    } else {        
        [PlatformType]::Windows    
    }
}

function Set-FilePermission
{    
    param(
        [parameter(Mandatory=$true)]
        [string]$FilePath,
        [parameter(Mandatory=$true)]
        [System.Security.Principal.SecurityIdentifier] $UserSid,
        [System.Security.AccessControl.FileSystemRights[]]$Perms,
        [System.Security.AccessControl.AccessControlType] $AccessType = "Allow",
        [ValidateSet("Add", "Delete")]
        [string]$Action = "Add"
    )    

    $myACL = Get-ACL $FilePath
    $account = Get-UserAccount -UserSid $UserSid
    if($Action -ieq "Delete")
    {
        $myACL.SetAccessRuleProtection($True, $True)
        Enable-Privilege SeRestorePrivilege | out-null
        Set-Acl -Path $FilePath -AclObject $myACL
        $myACL = Get-ACL $FilePath
        
        if($myACL.Access) 
        {        
            $myACL.Access | % {
                if($_.IdentityReference.Equals($account))
                {
                    if($_.IsInherited)
                    {
                        $myACL.SetAccessRuleProtection($True, $True)
                        Enable-Privilege SeRestorePrivilege | out-null
                        Set-Acl -Path $FilePath -AclObject $myACL
                        $myACL = Get-ACL $FilePath
                    }
                    
                    if(-not ($myACL.RemoveAccessRule($_)))
                    {
                        throw "failed to remove access of $($_.IdentityReference) rule in setup "
                    }
                }
            }
        } 
    }
    elseif($Perms)
    {
        $Perms | % { 
            $userACE = New-Object System.Security.AccessControl.FileSystemAccessRule `
                ($UserSid, $_, "None", "None", $AccessType)
            $myACL.AddAccessRule($userACE)
        }
    }
    Enable-Privilege SeRestorePrivilege | out-null
    Set-Acl -Path $FilePath -AclObject $myACL -confirm:$false
}

function Add-PasswordSetting 
{
    param([string] $pass)
    $platform = Get-Platform
    if ($platform -eq [PlatformType]::Windows) {
        if (-not($env:DISPLAY)) {$env:DISPLAY = 1}
        $askpass_util = Join-Path $PSScriptRoot "utilities\askpass_util\askpass_util.exe"
        $env:SSH_ASKPASS=$askpass_util
        $env:ASKPASS_PASSWORD=$pass
        $env:SSH_ASKPASS_REQUIRE="prefer"
    }
}

function Remove-PasswordSetting
{
    if ($env:DISPLAY -eq 1) { Remove-Item env:\DISPLAY -ErrorAction SilentlyContinue }
    Remove-item "env:SSH_ASKPASS" -ErrorAction SilentlyContinue
    Remove-item "env:ASKPASS_PASSWORD" -ErrorAction SilentlyContinue
    Remove-item "env:SSH_ASKPASS_REQUIRE" -ErrorAction SilentlyContinue
}

$Taskfolder = "\OpenSSHTestTasks\"
$Taskname = "StartTestDaemon"
        
function Start-SSHDTestDaemon
{
    param(
    [string] $Arguments,
    [string] $Workdir,
    [string] $Port)    

    $Arguments += " -p $Port"
    $ac = New-ScheduledTaskAction -Execute (join-path $workdir "sshd") -WorkingDirectory $workdir -Argument $Arguments
    $task = Register-ScheduledTask -TaskName $Taskname -User system -Action $ac -TaskPath $Taskfolder -Force    
    Start-ScheduledTask -TaskPath $Taskfolder -TaskName $Taskname
    #sleep for 1 seconds for process to ready to listener
    $num = 0
    while ((netstat -anop TCP | select-string -Pattern "0.0.0.0:$Port") -eq $null)
    {
        start-sleep 1
        $num++
        if($num -gt 30) { break }
    }
}

function Stop-SSHDTestDaemon
{
    param(
    [string] $Port) 

    $task = Get-ScheduledTask -TaskPath $Taskfolder -TaskName $Taskname -ErrorAction SilentlyContinue
    if($task)
    {
        if($task.State -eq "Running")
        {
            Stop-ScheduledTask -TaskPath $Taskfolder -TaskName $Taskname
        }        
        Unregister-ScheduledTask -TaskPath $Taskfolder -TaskName $Taskname -Confirm:$false
    }

    #kill process listening on $Port
    $p = netstat -anop TCP | select-string -Pattern "0.0.0.0:$Port"
    if (-not($p -eq $null)) 
    {
        foreach ($ps in $p) {
            $pss =$ps.ToString() -split "\s+"; 
            $pid = $pss[$pss.length -1] 
            Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue
        }
        #if still running, wait a little while for task to complete
        $num = 0
        while (-not((netstat -anop TCP | select-string -Pattern "0.0.0.0:$Port") -eq $null))
        {
            start-sleep 1
            $num++
            if($num -gt 30) { break }
        }
    }

}