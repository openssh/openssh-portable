If ($PSVersiontable.PSVersion.Major -le 2) {$PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path}
Import-Module $PSScriptRoot\CommonUtils.psm1 -Force
$suite = "Setup"
$tC = 1
$tI = 0
Describe "Setup Tests" -Tags "Setup" {
    BeforeAll {
        if($OpenSSHTestInfo -eq $null)
        {
            Throw "`$OpenSSHTestInfo is null. Please run Set-OpenSSHTestEnvironment to set test environments."
        }     
        
        $windowsInBox = $OpenSSHTestInfo["WindowsInBox"]
        $binPath = $OpenSSHTestInfo["OpenSSHBinPath"]
        $dataPath = Join-path $env:ProgramData ssh        
        
        $systemSid = Get-UserSID -WellKnownSidType ([System.Security.Principal.WellKnownSidType]::LocalSystemSid)
        $adminsSid = Get-UserSID -WellKnownSidType ([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid)
        $usersSid = Get-UserSID -WellKnownSidType ([System.Security.Principal.WellKnownSidType]::BuiltinUsersSid)
        $authenticatedUserSid = Get-UserSID -WellKnownSidType ([System.Security.Principal.WellKnownSidType]::AuthenticatedUserSid)
        $trustedInstallerSid = Get-UserSID -User "NT SERVICE\TrustedInstaller"
        $allApplicationPackagesSid = Get-UserSID -User "ALL APPLICATION PACKAGES"
        $allRestrictedApplicationPackagesSid = Get-UserSID -User "ALL RESTRICTED APPLICATION PACKAGES"

        $FSReadAccessPerm = ([System.UInt32] [System.Security.AccessControl.FileSystemRights]::ReadAndExecute.value__)  -bor `
                    ([System.UInt32] [System.Security.AccessControl.FileSystemRights]::Synchronize.value__)
        $FSReadWriteAccessPerm = ([System.UInt32] [System.Security.AccessControl.FileSystemRights]::ReadAndExecute.value__)  -bor `
                ([System.UInt32] [System.Security.AccessControl.FileSystemRights]::Write.value__)  -bor `
                ([System.UInt32] [System.Security.AccessControl.FileSystemRights]::Modify.value__)  -bor `
                ([System.UInt32] [System.Security.AccessControl.FileSystemRights]::Synchronize.value__)

        $FSFullControlPerm = [System.UInt32] [System.Security.AccessControl.FileSystemRights]::FullControl.value__
        $FSReadAndExecutePerm = ([System.UInt32] [System.Security.AccessControl.FileSystemRights]::ReadAndExecute.value__)  -bor `
                ([System.UInt32] [System.Security.AccessControl.FileSystemRights]::Synchronize.value__)

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
                    (([System.Int32]$a.RegistryRights.value__) -eq ($_.RegistryRights))
                }
                $findItem | Should Not Be $null
            }

            foreach ($expected in $IdAcls) {
                $findItem = $nonPropagate | ? {
                    ((Get-UserAccount -UserSid ($expected.Identity)) -eq $_.IdentityReference) -and `
                    ($expected.IsInherited -eq $_.IsInherited) -and `                    
                    ($expected.RegistryRights -eq ([System.Int32]$_.RegistryRights.value__))
                }
                $findItem | Should Not Be $null
            }            
        }

        #only validate owner and ACEs of the file
        function ValidateFileSystem {
            param(
                [string]$FilePath,
                [bool]$IsDirectory = $false,
                [switch]$IsDataFile,
                $OwnerSid = $trustedInstallerSid)

            if($IsDirectory)
            {
                Test-Path -Path $FilePath -PathType Container | Should Be $true
            }
            else
            {
                Test-Path -Path $FilePath -PathType Leaf | Should Be $true
            }

            $myACL = Get-ACL $FilePath
            $currentOwnerSid = Get-UserSid -User $myACL.Owner
            if(-not $windowsInBox) {return}            
            $currentOwnerSid.Equals($OwnerSid) | Should Be $true            
            $myACL.Access | Should Not Be $null
            if($IsDirectory)
            {
                $identities = @($systemSid, $adminsSid)
            }
            elseif($IsDataFile)
            {
                $identities = @($systemSid, $adminsSid, $authenticatedUserSid)
            }
            else
            {
                $identities = @($systemSid, $adminsSid, $trustedInstallerSid, $allApplicationPackagesSid, $allRestrictedApplicationPackagesSid, $usersSid)
            }

            $identities | % {
                $myACL.Access.IdentityReference -contains (Get-UserAccount -UserSid $_) | Should Be $true
            }

            foreach ($a in $myACL.Access) {
                $id = Get-UserSid -User $a.IdentityReference
                if($id -eq $null)
                {
                    $idRefShortValue = ($a.IdentityReference.Value).split('\')[-1]
                    $id = Get-UserSID -User $idRefShortValue                                      
                }

                $identities -contains $id | Should be $true

                switch ($id)
                {
                    {@($systemSid, $adminsSid) -contains $_}
                    {
                        if($IsDataFile)
                        {
                            ([System.UInt32]$a.FileSystemRights.value__) | Should Be $FSFullControlPerm
                        }
                        else
                        {
                            ([System.UInt32]$a.FileSystemRights.value__) | Should Be $FSReadAndExecutePerm
                        }                        
                        break;
                    }
                    {@($usersSid, $allApplicationPackagesSid, $allRestrictedApplicationPackagesSid, $authenticatedUserSid) -contains $_}
                    {                        
                        ([System.UInt32]$a.FileSystemRights.value__) | Should Be $FSReadAndExecutePerm                     
                        break;
                    }
                    $trustedInstallerSid
                    {
                        ([System.UInt32]$a.FileSystemRights.value__) | Should Be $FSFullControlPerm
                        break;
                    }
                }
            
                $a.AccessControlType | Should Be ([System.Security.AccessControl.AccessControlType]::Allow)
                if($IsDirectory)
                {
                    $a.InheritanceFlags | Should Be (([System.Security.AccessControl.InheritanceFlags]::ContainerInherit.value__ -bor `
                         [System.Security.AccessControl.InheritanceFlags]::ObjectInherit.value__))
                }
                else
                {
                    $a.InheritanceFlags | Should Be ([System.Security.AccessControl.InheritanceFlags]::None)
                }
                $a.PropagationFlags | Should Be ([System.Security.AccessControl.PropagationFlags]::None)
            }
        }        
    }    

    Context "$tC - Validate Openssh binary files" {

        BeforeAll {
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
            $dataFile =  @(
                @{
                    Name = 'sshd_config_default'
                },
                @{
                    Name = 'install-sshd.ps1'
                },
                @{
                    Name = 'uninstall-sshd.ps1'
                },
                @{
                    Name = 'FixHostFilePermissions.ps1'
                },
                @{
                    Name = 'FixUserFilePermissions.ps1'
                },
                @{
                    Name = 'OpenSSHUtils.psm1'
                },
                @{
                    Name = 'OpenSSHUtils.psd1'
                },
                @{
                    Name = 'openssh-events.man'
                }
            )

            $dataFile1 = @(
                @{
                    Name = "sshd_config"
                }
                @{
                    Name = "logs"
                    IsDirectory = $true
                }
            )
        }
        AfterAll{$tC++}        
        AfterEach { $tI++ }

        It "$tC.$tI - Validate Openssh binary files--<Name>" -TestCases:$binaries{
            param([string]$Name, [boolean]$IsDirectory = $false)
            ValidateFileSystem -FilePath (join-path $binPath $Name)
        }
        It "$tC.$tI - Validate Openssh script files--<Name>" -TestCases:$dataFile {
            param([string]$Name, [boolean]$IsDirectory = $false)            
            if(-not $WindowsInbox) { ValidateFileSystem -FilePath (join-path $binPath $Name) }
        }

        It "$tC.$tI - Validate data files--<Name>" -TestCases:$dataFile1 {
            param([string]$Name, [boolean]$IsDirectory = $false)
            if(-not (Test-Path $dataPath -PathType Container))
            {
                Start-Service sshd
            }
            
            ValidateFileSystem -FilePath (join-path $dataPath $Name) -IsDirectory $IsDirectory -OwnerSid $adminsSid -IsDataFile
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

        It "$tC.$tI - Validate Registry key ssh-agent\Description" {
            $p = Get-ItemPropertyValue (Join-Path $servicePath "ssh-agent") -Name "Description"
            $p | Should Not Be $null
        }

        It "$tC.$tI - Validate Registry key ssh-agent\ErrorControl" {
            $p = Get-ItemPropertyValue (Join-Path $servicePath "ssh-agent") -Name "ErrorControl"
            $p | Should Be 1
        }

        It "$tC.$tI - Validate Registry key ssh-agent\ImagePath" {
            $p = Get-ItemPropertyValue (Join-Path $servicePath "ssh-agent") -Name "ImagePath"
            $imagePath = (Join-Path $binPath "ssh-agent.exe").ToLower()
            $p | Should Match "[`"]?$($imagePath.Replace("\", "\\"))[`"]?"
        }

        It "$tC.$tI - Validate Registry key ssh-agent\ObjectName" {
            $p = Get-ItemPropertyValue (Join-Path $servicePath "ssh-agent") -Name "ObjectName"
            $p | Should Be "LocalSystem"
        }        

        It "$tC.$tI - Validate Registry key ssh-agent\Start" {
            $p = Get-ItemPropertyValue (Join-Path $servicePath "ssh-agent") -Name "Start"  
            if($windowsInBox) {
                $p | Should Be 4
            }
            else {
                $p | Should Be 3
            }
        }

        It "$tC.$tI - Validate Registry key ssh-agent\Type" {
            $p = Get-ItemPropertyValue (Join-Path $servicePath "ssh-agent") -Name "Type"
            $p | Should Be 16
        }        

        It "$tC.$tI - Validate Registry key to ssh-agent\Security\Security" { 
            $p = Get-ItemPropertyValue (Join-Path $servicePath "ssh-agent\Security") -Name Security
            $p.Gettype() | Should Be byte[]
        }        

        It "$tC.$tI - Validate Registry key sshd\Description" {
            $p = Get-ItemPropertyValue (Join-Path $servicePath "sshd") -Name "Description"
            $p | Should not Be $null
        }

        It "$tC.$tI - Validate Registry key sshd\ErrorControl" {
            $p = Get-ItemPropertyValue (Join-Path $servicePath "sshd") -Name "ErrorControl"
            $p | Should Be 1
        }

        It "$tC.$tI - Validate Registry key sshd\ImagePath" {
            $p = Get-ItemPropertyValue (Join-Path $servicePath "sshd") -Name "ImagePath"
            $imagePath = (Join-Path $binPath "sshd.exe").ToLower()
            $p | Should Match "[`"]?$($imagePath.Replace("\", "\\"))[`"]?"
        }

        It "$tC.$tI - Validate Registry key sshd\ObjectName" {
            $p = Get-ItemPropertyValue (Join-Path $servicePath "sshd") -Name "ObjectName"            
            $p | Should Be "LocalSystem"
        }        

        It "$tC.$tI - Validate Registry key sshd\Start" {
            $p = Get-ItemPropertyValue (Join-Path $servicePath "sshd") -Name "Start"            
            $p | Should Be 3
        }

        It "$tC.$tI - Validate Registry key sshd\Type" {
            $p = Get-ItemPropertyValue (Join-Path $servicePath "sshd") -Name "Type"            
            $p | Should Be 16
        }

        It "$tC.$tI - Validate Registry openssh entry" {
            ValidateRegistryACL -RegPath $opensshRegPath -IdAcls $opensshACLs
        }
        It "$tC.$tI - Validate Registry openssh\agent entry" {
            $agentPath = Join-Path $opensshRegPath "Agent"
            if(Test-Path $agentPath -PathType Container)
            {
                ValidateRegistryACL -RegPath $agentPath -IdAcls $opensshACLs
            }
            elseif((-not $windowsInBox) -or ((Get-Service ssh-agent).StartType -ne ([System.ServiceProcess.ServiceStartMode]::Disabled)))
            {
                Start-Service ssh-agent
                ValidateRegistryACL -RegPath $agentPath -IdAcls $opensshACLs
            }                            
        }
    }

    Context "$tC - Validate service settings" {
        BeforeAll {            
            $tI=1
        }        
        AfterAll{$tC++}
        AfterEach { $tI++ }

        It "$tC.$tI - Validate properties of ssh-agent service" {            
            $sshdSvc = Get-service ssh-agent
            if($windowsInBox) {
                $sshdSvc.StartType | Should Be ([System.ServiceProcess.ServiceStartMode]::Disabled)
            }
            else {
                $sshdSvc.StartType | Should Be ([System.ServiceProcess.ServiceStartMode]::Manual)
            }
            $sshdSvc.ServiceType | Should Be ([System.ServiceProcess.ServiceType]::Win32OwnProcess)
            $sshdSvc.ServiceName | Should Be "ssh-agent"
            $sshdSvc.DisplayName | Should BeLike "OpenSSH*"
            $sshdSvc.Name | Should Be "ssh-agent"
            ($sshdSvc.DependentServices).Count | Should Be 0
            ($sshdSvc.ServicesDependedOn).Count | Should Be 0
            ($sshdSvc.RequiredServices).Count | Should Be 0
        }

        It "$tC.$tI - Validate properties of sshd service" {            
            $sshdSvc = Get-service sshd
            $sshdSvc.StartType | Should Be ([System.ServiceProcess.ServiceStartMode]::Manual)
            $sshdSvc.ServiceType | Should Be ([System.ServiceProcess.ServiceType]::Win32OwnProcess)
            $sshdSvc.ServiceName | Should Be "sshd"
            $sshdSvc.DisplayName | Should BeLike "OpenSSH*"
            $sshdSvc.Name | Should Be "sshd"
            ($sshdSvc.DependentServices).Count | Should Be 0
            ($sshdSvc.ServicesDependedOn).Count | Should Be 0
            ($sshdSvc.RequiredServices).Count | Should Be 0
        }
        
        It "$tC.$tI - Validate RequiredPrivileges of ssh-agent" {            
            $a = sc.exe qprivs ssh-agent 256
            $p = @($a | % { if($_ -match "Se[\w]+Privilege" ) {$start = $_.IndexOf("Se");$_.Substring($start, $_.length-$start)}})
            $p.count | Should Be 1
            $p[0] | Should Be "SeImpersonatePrivilege"
        }

        It "$tC.$tI - Validate RequiredPrivileges of sshd" {
            $expected = @("SeAssignPrimaryTokenPrivilege", "SeTcbPrivilege", "SeBackupPrivilege", "SeRestorePrivilege", "SeImpersonatePrivilege")
            $a = sc.exe qprivs sshd 256
            $p = $a | % { if($_ -match "Se[\w]+Privilege" ) {$start = $_.IndexOf("Se");$_.Substring($start, $_.length-$start)}}
            $expected | % {
                $p -contains $_ | Should be $true
            }

            $p | % {
                $expected -contains $_ | Should be $true
            }
        }

        It "$tC.$tI - Validate security access to ssh-agent service" {            
            $a = @(sc.exe sdshow ssh-agent)
            $b = $a[-1] -split "[D|S]:"

            $expected_dacl_aces = @("(A;;CCLCSWRPWPDTLOCRRC;;;SY)", "(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)", "(A;;CCLCSWLOCRRC;;;IU)", "(A;;CCLCSWLOCRRC;;;SU)", "(A;;RP;;;AU)")
            $c = @($b | ? { -not [string]::IsNullOrWhiteSpace($_) })
            $dacl = $c[0]
            $dacl_aces = $dacl -split "(\([;|\w]+\))"
            $actual_dacl_aces = $dacl_aces | ? { -not [string]::IsNullOrWhiteSpace($_) }

            $expected_dacl_aces | % {
                $actual_dacl_aces -contains $_ | Should be $true 
            }
            $actual_dacl_aces | % {
                $expected_dacl_aces -contains $_ | Should be $true
            }

            <# ignore sacl for now
            if($c.Count -gt 1) {                
                $c[1] | Should Be "(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)"            
            }#>
        }

        It "$tC.$tI - Validate security access to sshd service" {            
            $a = @(sc.exe sdshow sshd)
            $b = $a[-1] -split "[D|S]:"

            $expected_dacl_aces = @("(A;;CCLCSWRPWPDTLOCRRC;;;SY)", "(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)", "(A;;CCLCSWLOCRRC;;;IU)", "(A;;CCLCSWLOCRRC;;;SU)")
            $c = @($b | ? { -not [string]::IsNullOrWhiteSpace($_) })
            $dacl = $c[0]
            $dacl_aces = $dacl -split "(\([;|\w]+\))"
            $actual_dacl_aces = $dacl_aces | ? { -not [string]::IsNullOrWhiteSpace($_) }

            $expected_dacl_aces | % {
                $actual_dacl_aces -contains $_ | Should be $true
            }
            $actual_dacl_aces | % {
                $expected_dacl_aces -contains $_ | Should be $true
            }

            <# ignore sacl for now
            if($c.Count -gt 1) {                
                $c[1] | Should Be "(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)"            
            }#>
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
            $rule = Get-NetFirewallRule -Name $firwallRuleName            
            $rule.Group | Should BeLike "OpenSSH*"
            $rule.Description | Should BeLike "*OpenSSH*"
            $rule.DisplayName | Should BeLike "OpenSSH*"
            $rule.Enabled | Should Be $true
            $rule.Profile.ToString() | Should Be 'Any'
            $rule.Direction.ToString() | Should Be 'Inbound'
            $rule.Action.ToString() | Should Be 'Allow'
            $rule.StatusCode | Should Be 65536
            $fwportFilter = $rule | Get-NetFirewallPortFilter
            $fwportFilter.Protocol | Should Be 'TCP'
            $fwportFilter.LocalPort | Should Be 22
            $fwportFilter.RemotePort | Should Be 'Any'
        }        
    }
}
