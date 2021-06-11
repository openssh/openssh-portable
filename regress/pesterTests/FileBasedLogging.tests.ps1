If ($PSVersiontable.PSVersion.Major -le 2) {$PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path}
Import-Module $PSScriptRoot\CommonUtils.psm1 -Force
Import-Module OpenSSHUtils -Force
$tC = 1
$tI = 0
$suite = "FileBasedLogging"
Describe "Tests for admin and non-admin file based logs" -Tags "CI" {
    BeforeAll {
        if($OpenSSHTestInfo -eq $null)
        {
            Throw "`$OpenSSHTestInfo is null. Please run Set-OpenSSHTestEnvironment to set test environments."
        }
        
        $testDir = "$($OpenSSHTestInfo["TestDataPath"])\$suite"
        if( -not (Test-path $testDir -PathType Container))
        {
            $null = New-Item $testDir -ItemType directory -Force -ErrorAction SilentlyContinue
        }        

        $sshLogName = "test.txt"
        $sshdLogName = "sshdlog.txt"
        $server = $OpenSSHTestInfo["Target"]
        $opensshbinpath = $OpenSSHTestInfo['OpenSSHBinPath']
        $nonadminusername = $OpenSSHTestInfo['NonAdminUser']
        $adminusername = $OpenSSHTestInfo['AdminUser']
        $password = $OpenSSHTestInfo['TestAccountPW']
        $port = 47003  
        $sshdDelay = $OpenSSHTestInfo["DelayTime"]		
        Remove-Item -Path (Join-Path $testDir "*$sshLogName") -Force -ErrorAction SilentlyContinue

        <# Setup sshd_config file#>
        
        $sshdconfig_ori = Join-Path $Global:OpenSSHTestInfo["ServiceConfigDir"] sshd_config
        $sshdconfig_custom = Join-Path $Global:OpenSSHTestInfo["ServiceConfigDir"] sshd_config_custom
        if (Test-Path $sshdconfig_custom) {
            Remove-Item $sshdconfig_custom -Force
        }
        Copy-Item $sshdconfig_ori $sshdconfig_custom
        get-acl $sshdconfig_ori | set-acl $sshdconfig_custom
        $content = Get-Content -Path $sshdconfig_custom
        $newContent = $content -replace "Subsystem	sftp	sftp-server.exe -l DEBUG3", "Subsystem	sftp	sftp-server.exe -l DEBUG3 -f LOCAL0"
        $newContent | Set-Content -Path $sshdconfig_custom

        #skip when the task schedular (*-ScheduledTask) cmdlets does not exist
        $ts = (get-command get-ScheduledTask -ErrorAction SilentlyContinue)
        $skip = $ts -eq $null
        if(-not $skip)
        {
            Stop-SSHDTestDaemon   -Port $port
        }
        if(($platform -eq [PlatformType]::Windows) -and ([Environment]::OSVersion.Version.Major -le 6))
        {
            #suppress the firewall blocking dialogue on win7
            netsh advfirewall firewall add rule name="sshd" program="$($OpenSSHTestInfo['OpenSSHBinPath'])\sshd.exe" protocol=any action=allow dir=in
        }
    }

    AfterEach { $tI++ }
    
    AfterAll {        
        if(($platform -eq [PlatformType]::Windows) -and ($psversiontable.BuildVersion.Major -le 6))
        {            
            netsh advfirewall firewall delete rule name="sshd" program="$($OpenSSHTestInfo['OpenSSHBinPath'])\sshd.exe" protocol=any dir=in
        }    
    }


    Context "Tests Logs for SSH connections" {
        BeforeAll {            
            $sshdConfigPath = $sshdconfig_custom
            Add-PasswordSetting -Pass $password
            $tI=1
        }
        
        BeforeEach {
            $sshlog = Join-Path $testDir "$tC.$tI.$sshLogName"            
            $sshdlog = Join-Path $testDir "$tC.$tI.$sshdLogName"

            if (Test-Path $sshdlog -PathType Leaf) {
                Clear-Content $sshdlog
            }

            if(-not $skip)
            {
                Stop-SSHDTestDaemon   -Port $port
            }
        }

        AfterAll {            
            Remove-PasswordSetting
            $tC++
        }

        It "$tC.$tI-Nonadmin SSH Connection"  -skip:$skip {
            Start-SSHDTestDaemon -WorkDir $opensshbinpath -Arguments "-ddd -f $sshdConfigPath -E $sshdlog" -Port $port
            $o = ssh -vvv -p $port -E $sshlog $nonadminusername@$server echo 1234
            $o | Should Be 1234
            Stop-SSHDTestDaemon   -Port $port
            sleep $sshdDelay
            $sshdlog | Should Contain "KEX done \[preauth\]"
            $sshdlog | Should Contain "exec_command: echo 1234"
        }

        It "$tC.$tI-Admin SSH Connection"  -skip:$skip {
            Start-SSHDTestDaemon -WorkDir $opensshbinpath -Arguments "-ddd -f $sshdConfigPath -E $sshdlog" -Port $port
            $o = ssh -vvv -p $port -E $sshlog $adminusername@$server echo 1234
            $o | Should Be 1234
            Stop-SSHDTestDaemon   -Port $port
            sleep $sshdDelay
            $sshdlog | Should Contain "KEX done \[preauth\]"
            $sshdlog | Should Contain "exec_command: echo 1234"
        }
    }

    Context "Tests Logs for SFTP connections" {

        BeforeAll {
            $sshdConfigPath = $sshdconfig_custom

            function Setup-KeyBasedAuth
            {
                param([string] $Username, [string] $KeyFilePath, [string] $UserProfile)

                $userSSHProfilePath = Join-Path $UserProfile .ssh

                if (-not (Test-Path $userSSHProfilePath -PathType Container)) {
                    New-Item $userSSHProfilePath -ItemType directory -Force -ErrorAction Stop | Out-Null
                }

                $authorizedkeyPath = Join-Path $userSSHProfilePath authorized_keys

                if($OpenSSHTestInfo["NoLibreSSL"])
                {
                    ssh-keygen.exe -t ed25519 -f $KeyFilePath -Z -P `"`" aes128-ctr
                }
                else
                {
                    ssh-keygen.exe -t ed25519 -f $KeyFilePath -P `"`"
                }
                Copy-Item "$keyFilePath.pub" $authorizedkeyPath -Force -ErrorAction SilentlyContinue
                Repair-AuthorizedKeyPermission -Filepath $authorizedkeyPath -confirm:$false
            }

            $AdminUserProfile = $OpenSSHTestInfo['AdminUserProfile']
            $NonAdminUserProfile = $OpenSSHTestInfo['NonAdminUserProfile']

            $KeyFileName = $nonadminusername + "_sshtest_fileBasedLog_ed25519"
            $NonadminKeyFilePath = Join-Path $testDir $keyFileName
            Remove-Item -path "$NonadminKeyFilePath*" -Force -ErrorAction SilentlyContinue
            Setup-KeyBasedAuth -Username $nonadminusername -KeyFilePath $NonadminKeyFilePath -UserProfile $NonAdminUserProfile

            $KeyFileName = $adminusername + "_sshtest_fileBasedLog_ed25519"
            $AdminKeyFilePath = Join-Path $testDir $keyFileName
            Remove-Item -path "$AdminKeyFilePath*" -Force -ErrorAction SilentlyContinue
            Setup-KeyBasedAuth -Username $adminusername -KeyFilePath $AdminKeyFilePath -UserProfile $AdminUserProfile

            #create batch file
            $commands = 
"ls
exit"
            $batchFilePath = Join-Path $testDir "$tC.$tI.commands.txt"
            Set-Content $batchFilePath -Encoding UTF8 -value $commands

            $tI = 1
        }

        BeforeEach {
            Clear-Content "$env:ProgramData\ssh\logs\sftp-server.log" -Force -ErrorAction SilentlyContinue
            $sshlog = Join-Path $testDir "$tC.$tI.$sshLogName"            
            $sshdlog = Join-Path $testDir "$tC.$tI.$sshdLogName"
            if (Test-Path $sshdlog -PathType Leaf) {
                Clear-Content $sshdlog
            }
            if(-not $skip)
            {
                Stop-SSHDTestDaemon   -Port $port
            }
        }

        AfterAll {
            Remove-Item -path "$NonadminKeyFilePath*" -Force -ErrorAction SilentlyContinue
            Remove-Item -path "$AdminKeyFilePath*" -Force -ErrorAction SilentlyContinue

            $authorized_key = Join-Path .ssh authorized_keys
            $AdminAuthKeysPath = Join-Path $AdminUserProfile $authorized_key
            $NonAdminAuthKeysPath = Join-Path $NonAdminUserProfile $authorized_key
            Remove-Item -path "$AdminAuthKeysPath*" -Force -ErrorAction SilentlyContinue
            Remove-Item -path "$NonAdminAuthKeysPath*" -Force -ErrorAction SilentlyContinue

            $tC++
        }

        It "$tC.$tI-Nonadmin SFTP Connection"  -skip:$skip {
            Start-SSHDTestDaemon -WorkDir $opensshbinpath -Arguments "-ddd -f $sshdConfigPath -E $sshdlog" -Port $port
            sftp -P $port -i $NonadminKeyFilePath -b $batchFilePath $nonadminusername@$server
            Stop-SSHDTestDaemon   -Port $port
            sleep $sshdDelay
            $sftplog = Join-Path $testDir "$tC.$tI.sftp-server.log"
            Copy-Item "$env:ProgramData\ssh\logs\sftp-server.log" $sftplog -Force -ErrorAction SilentlyContinue

            $sshdlog | Should Contain "Accepted publickey for $nonadminusername"
            $sshdlog | Should Contain "KEX done \[preauth\]"
            $sshdlog | Should Contain "debug2: subsystem request for sftp by user $nonadminusername"
            $sftplog | Should Contain "session opened for local user $nonadminusername"
            $sftplog | Should Contain "debug3: request 3: opendir"
            $sftplog | Should Contain "session closed for local user $nonadminusername"
        }

        It "$tC.$tI-Admin SFTP Connection"  -skip:$skip {	
            Start-SSHDTestDaemon -WorkDir $opensshbinpath -Arguments "-ddd -f $sshdConfigPath -E $sshdlog" -Port $port
            sftp -P $port -i $AdminKeyFilePath -b $batchFilePath $adminusername@$server
            Stop-SSHDTestDaemon   -Port $port
            sleep $sshdDelay
            $sftplog = Join-Path $testDir "$tC.$tI.sftp-server.log"
            Copy-Item "$env:ProgramData\ssh\logs\sftp-server.log" $sftplog -Force -ErrorAction SilentlyContinue
  
            $sshdlog | Should Contain "Accepted publickey for $adminusername"
            $sshdlog | Should Contain "KEX done \[preauth\]"
            $sshdlog | Should Contain "debug2: subsystem request for sftp by user $adminusername"
            $sftplog | Should Contain "session opened for local user $adminusername"
            $sftplog | Should Contain "debug3: request 3: opendir"
            $sftplog | Should Contain "session closed for local user $adminusername"
        }
    }
}
