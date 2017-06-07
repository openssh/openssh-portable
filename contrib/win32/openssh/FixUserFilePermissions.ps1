param ([switch]$Quiet)
If (!(Test-Path variable:PSScriptRoot)) {$PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition}

Import-Module $PSScriptRoot\OpenSSHUtils.psm1 -Force -DisableNameChecking

if(Test-Path ~\.ssh\config -PathType Leaf)
{
    Fix-UserSSHConfigPermissions -FilePath ~\.ssh\config @psBoundParameters
}

Get-ChildItem ~\.ssh\* -Include "id_rsa","id_dsa" -ErrorAction SilentlyContinue | % {
    Fix-UserKeyPermissions -FilePath $_.FullName @psBoundParameters
}

Write-Host "   Done."
Write-Host " "
