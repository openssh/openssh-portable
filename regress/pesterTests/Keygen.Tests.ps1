Describe "Tests for ssh-keygen" -Tags "CI" {
    BeforeAll {    
        if($OpenSSHTestInfo -eq $null)
        {
            Throw "`$OpenSSHTestInfo is null. Please run Setup-OpenSSHTestEnvironment to setup test environment."
        }
        
        $testDir = "$($OpenSSHTestInfo["TestDataPath"])\keygen"
        if( -not (Test-path $testDir -PathType Container))
        {
            $null = New-Item $testDir -ItemType directory -Force -ErrorAction SilentlyContinue
        }        
        #only validate owner and ACE of the file
        function ValidKeyFile {
            param($Path)

            $currentUser = New-Object System.Security.Principal.NTAccount($($env:USERDOMAIN), $($env:USERNAME))
            $myACL = Get-ACL $Path
            $myACL.Owner.Equals($currentUser.Value) | Should Be $true
            $myACL.Access | Should Not Be $null
            $myACL.Access.Count | Should Be 1
            
            $myACL.Access[0].IdentityReference.Equals($currentUser) | Should Be $true
            $myACL.Access[0].AccessControlType | Should Be ([System.Security.AccessControl.AccessControlType]::Allow)
            $myACL.Access[0].FileSystemRights | Should Be ([System.Security.AccessControl.FileSystemRights]::FullControl)
            $myACL.Access[0].IsInherited | Should Be $false
            $myACL.Access[0].InheritanceFlags | Should Be ([System.Security.AccessControl.InheritanceFlags]::None)
            $myACL.Access[0].PropagationFlags | Should Be ([System.Security.AccessControl.PropagationFlags]::None)            
        }
    }

    Context "Keygen key files" {
        BeforeEach {
            Remove-Item $testDir\* -Force -ErrorAction ignore
            Remove-Item "$PSScriptRoot\ssh_host_*_key*" -Force -ErrorAction ignore
        }

        It 'Keygen -A' {
            ssh-keygen -A
            
            Get-ChildItem "$PSScriptRoot\ssh_host_*_key" | % {
                ValidKeyFile -Path $_.FullName
            }

            Get-ChildItem "$PSScriptRoot\ssh_host_*_key.pub" | % {
                ValidKeyFile -Path $_.FullName
            }
        }

        It 'Keygen -t -f' {
            $pwd = "testpassword"

            foreach($type in @("rsa","dsa","ecdsa","ed25519"))
            {
                $keyPath = Join-Path $testDir "id_$type"                
                ssh-keygen -t $type -P $pwd -f $keyPath
                ValidKeyFile -Path $keyPath
                ValidKeyFile -Path "$keyPath.pub"
            }
        }
    }
}
