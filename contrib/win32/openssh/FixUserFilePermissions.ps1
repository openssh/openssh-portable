[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact="High")]
param ()
Set-StrictMode -Version 2.0
If ($PSVersiontable.PSVersion.Major -le 2) {$PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path}

Import-Module $PSScriptRoot\OpenSSHUtils -Force

if(Test-Path ~\.ssh\config -PathType Leaf)
{
    Repair-UserSshConfigPermission -FilePath ~\.ssh\config @psBoundParameters
}

Get-ChildItem ~\.ssh\* -Include "id_rsa","id_dsa","id_ecdsa","id_ed25519" -ErrorAction SilentlyContinue | ForEach-Object {
    Repair-UserKeyPermission -FilePath $_.FullName @psBoundParameters
}



$sshdAdministratorsAuthorizedKeysPath = join-path $env:ProgramData\ssh "administrators_authorized_keys"
if(Test-Path $sshdAdministratorsAuthorizedKeysPath -PathType Leaf) 
{
    if (([bool]([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")))
    {
        Repair-AdministratorsAuthorizedKeysPermission -FilePath $sshdAdministratorsAuthorizedKeysPath @psBoundParameters
    }
    else 
    {
        Write-host "To fix file permissions for $sshdAdministratorsAuthorizedKeysPath, run this script in elevated mode" -ForegroundColor Yellow
    }
}



Write-Host "   Done."
Write-Host " "
