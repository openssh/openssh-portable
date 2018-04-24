If ($PSVersiontable.PSVersion.Major -le 2) {$PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path}
Import-Module $PSScriptRoot\CommonUtils.psm1 -Force
$suite = "Uninstall"
$tC = 1
$tI = 0
Describe "Uninstall Tests" -Tags "Uninstall" {
    BeforeAll {
        if($OpenSSHTestInfo -eq $null)
        {
            Throw "`$OpenSSHTestInfo is null. Please run Set-OpenSSHTestEnvironment to set test environments."
        }      
        
        $windowsInBox = $OpenSSHTestInfo["WindowsInBox"]
        $binPath = $OpenSSHTestInfo["OpenSSHBinPath"]
        $dataPath = Join-path $env:ProgramData ssh        

        Stop-Service sshd -ErrorAction SilentlyContinue
        Stop-Service ssh-agent -ErrorAction SilentlyContinue
        if(Get-Service sshd -ErrorAction SilentlyContinue)
        {        
            if($windowsInBox) {
                Remove-WindowsCapability -online -name OpenSSH.Server~~~~0.0.1.0
            }
            else {
                & (Join-Path $binPath "uninstall-sshd.ps1")
            }
        }
        if(Get-Service ssh-agent -ErrorAction SilentlyContinue)
        {
            if($windowsInBox) {
                Remove-WindowsCapability -online -name OpenSSH.Client~~~~0.0.1.0
            }
            else
            {
                & (Join-Path $binPath "uninstall-sshd.ps1")
            }
        }
        
        
        $systemSid = Get-UserSID -WellKnownSidType ([System.Security.Principal.WellKnownSidType]::LocalSystemSid)
        $adminsSid = Get-UserSID -WellKnownSidType ([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid)        
        $authenticatedUserSid = Get-UserSID -WellKnownSidType ([System.Security.Principal.WellKnownSidType]::AuthenticatedUserSid)        

        $RegReadKeyPerm = ([System.UInt32] [System.Security.AccessControl.RegistryRights]::ReadKey.value__)
        $RegFullControlPerm = [System.UInt32] [System.Security.AccessControl.RegistryRights]::FullControl.value__        

        #only validate owner and ACEs of the registry
        function ValidateRegistryACL {
            param([string]$RegPath, $Ownersid = $adminsSid, $IdAcls)
            Test-Path -Path $RegPath | Should Be $true                      
            $myACL = Get-ACL $RegPath
            $OwnerSid = Get-UserSid -User $myACL.Owner
            $OwnerSid.Equals($Ownersid) | Should Be $true
            $myACL.Access | Should Not Be $null
            $CAPABILITY_SID = "S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681"            
            $nonPropagate = $myACL.Access | ? {($_.PropagationFlags -eq ([System.Security.AccessControl.PropagationFlags]::None)) -and ($_.IdentityReference -ine $CAPABILITY_SID)}

            foreach ($a in $nonPropagate) {
                $findItem = $IdAcls | ? {
                    ($a.IdentityReference -eq (Get-UserAccount -UserSid ($_.Identity))) -and `
                    ($a.IsInherited -eq $_.IsInherited) -and `
                    ($a.AccessControlType -eq ([System.Security.AccessControl.AccessControlType]::Allow)) -and  `
                    ($a.PropagationFlags -eq ([System.Security.AccessControl.PropagationFlags]::None) -and  `
                    (([System.Int32]$a.RegistryRights.value__) -eq ($_.RegistryRights))) 
                }
                $findItem | Should Not Be $null
            }         
        }    
    }    

    Context "$tC - Validate Openssh binary files" {
        BeforeAll {
            if(-not $Windowsbox)
            {
                $binaries =  $null                
                return
            }
            $tI=1
            $binaries =  @(
                @{
                    Name = 'sshd.exe'
                },
                @{
                    Name = 'ssh.exe'
                },
                @{
                    Name = 'ssh-agent.exe'
                },
                @{
                    Name = 'ssh-add.exe'
                },
                @{
                    Name = 'sftp.exe'
                },
                @{
                    Name = 'sftp-server.exe'
                },
                @{
                    Name = 'scp.exe'
                },
                @{
                    Name = 'ssh-shellhost.exe'
                },
                @{
                    Name = 'ssh-agent.exe'
                },
                @{
                    Name = 'ssh-keyscan.exe'
                }
            )
        }
        AfterAll{$tC++}        
        AfterEach { $tI++ }

        It "$tC.$tI - Validate Openssh binary files--<Name> is removed" -TestCases:$binaries{
            param([string]$Name, [boolean]$IsDirectory = $false)
            if(-not [string]::IsNullOrWhiteSpace($Name)) {
                (join-path $binPath $Name) | Should Not Exist
            }
        }        
    } 
    
    Context "$tC - Validate Openssh registry entries" {
        BeforeAll {
            $tI=1
            $servicePath = "HKLM:\SYSTEM\ControlSet001\Services"
            $opensshRegPath = "HKLM:\SOFTWARE\OpenSSH"
            
            $opensshACLs = @(
                @{
                    Identity=$systemSid
                    IsInherited = $false
                    RegistryRights = $RegFullControlPerm
                    PropagationFlags = "None"
                },
                @{
                    Identity=$adminsSid
                    IsInherited = $false
                    RegistryRights = $RegFullControlPerm
                    PropagationFlags = "None"
                },                
                @{
                    Identity=$authenticatedUserSid
                    IsInherited = $false
                    RegistryRights = $RegReadKeyPerm -bor ([System.UInt32] [System.Security.AccessControl.RegistryRights]::SetValue.value__)
                    PropagationFlags = "None"
                }
            )
        }        
        AfterAll{$tC++}
        AfterEach { $tI++ }               

        It "$tC.$tI - Validate Registry key ssh-agent is removed" {
            (Join-Path $servicePath "ssh-agent") | Should Not Exist
        }

        It "$tC.$tI - Validate Registry key sshd is removed" {
            (Join-Path $servicePath "sshd") | Should Not Exist
        }

        It "$tC.$tI - Validate Registry openssh entry" {
            ValidateRegistryACL -RegPath $opensshRegPath -IdAcls $opensshACLs
        }       
    }

    Context "$tC - Validate service is removed" {
        BeforeAll {            
            $tI=1
        }
        
        AfterAll{$tC++}
        AfterEach { $tI++ }

        It "$tC.$tI - Validate ssh-agent is removed" {
            Get-Service ssh-agent -ErrorAction SilentlyContinue | Should Be $null
        }

        It "$tC.$tI - Validate sshd is removed" {
            Get-Service sshd -ErrorAction SilentlyContinue | Should Be $null
        }
    }

    Context "$tC - Validate Firewall settings" {
        BeforeAll {
            $firwallRuleName = "OpenSSH-Server-In-TCP"
            $tI=1
        }
        
        AfterAll{$tC++}
        AfterEach { $tI++ }

        It "$tC.$tI - Validate Firewall settings" -skip:(!$windowsInBox) {
            Get-NetFirewallRule -Name $firwallRuleName -ErrorAction SilentlyContinue | Should Be $null
        }        
    }    
}
