If ($PSVersiontable.PSVersion.Major -le 2) {$PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path}
Import-Module $PSScriptRoot\CommonUtils.psm1 -Force
$tC = 1
$tI = 0
$suite = "certauth"
        
Describe "E2E scenarios for certificate authentication" -Tags "CI" {
    BeforeAll {        
        if($OpenSSHTestInfo -eq $null)
        {
            Throw "`$OpenSSHTestInfo is null. Please run Set-OpenSSHTestEnvironment to set test environments."
        }

        $server = $OpenSSHTestInfo["Target"]
        $port = $OpenSSHTestInfo["Port"]
        $pkuser = $OpenSSHTestInfo["PubKeyUser"]
        $cakey = $OpenSSHTestInfo["CA_Private_Key"]
        $opensshbinpath = $OpenSSHTestInfo['OpenSSHBinPath']
        $ssouser = $OpenSSHTestInfo["SSOUser"]
        $sshdconfig = Join-Path $Global:OpenSSHTestInfo["ServiceConfigDir"] sshd_config
        
        $testDir = Join-Path $OpenSSHTestInfo["TestDataPath"] $suite
        if(-not (Test-Path $testDir))
        {
            $null = New-Item $testDir -ItemType directory -Force -ErrorAction SilentlyContinue
        }
        $user_key = Join-Path $testDir "cert_auth_user_key"
        $keypassphrase = "testpassword"        
    }

    BeforeEach {
        $stderrFile=Join-Path $testDir "$tC.$tI.stderr.txt"
        $stdoutFile=Join-Path $testDir "$tC.$tI.stdout.txt"
        $logFile = Join-Path $testDir "$tC.$tI.log.txt"
    }        

    AfterEach {$tI++;}

    Context "$tC - generate certificates" {
        
        BeforeAll {$tI=1}
        AfterAll{$tC++}

        It "$tC.$tI - sign user keys" {
            Remove-Item "$($user_key)*"
            ssh-keygen -t ed25519 -f $user_key  -P $keypassphrase
            $user_key | Should Exist
            $nullFile = join-path $testDir ("$tC.$tI.nullfile")
            $null > $nullFile
            $user_key_pub = ($user_key + ".pub")
            iex "cmd /c `"ssh-keygen -s $cakey -I $pkuser -V -1w:+54w5d  -n $pkuser $user_key_pub < $nullFile 2> nul `""
        }

    }

    Context "$tC - ssh with certificate" {
        BeforeAll {$tI=1}
        AfterAll{$tC++}

        It "$tC.$tI - authenticate using certificate" {
            #set up SSH_ASKPASS for key passphrase
            Add-PasswordSetting -Pass $keypassphrase
            $o = ssh -i $user_key -p $port $pkuser@$server echo 1234
            $o | Should Be "1234"
            Remove-PasswordSetting            
        }

        It "$tC.$tI - authenticate using certificate via AuthorizedPrincipalsCommand" {
            $pcOutFile = Join-Path $testDir "$tC.$tI.pcout.txt"
            $logFile = Join-Path $testDir "$tC.$tI.log.txt"
            Remove-Item -Force $pcOutFile -ErrorAction SilentlyContinue
            $sshdArgs = "-d -f $sshdconfig  -E $logFile -o `"AuthorizedKeysFile .fake/authorized_keys`""
            $sshdArgs += " -o `"AuthorizedPrincipalsCommand=$env:windir\system32\cmd.exe /c echo otheruser& echo $pkuser& whoami > $pcOutFile`""
            $sshdArgs += " -o `"AuthorizedPrincipalsCommandUser=$ssouser`""
            $sshdArgs += " -o PasswordAuthentication=no"

            Start-SSHDTestDaemon -WorkDir $opensshbinpath -Arguments $sshdArgs -Port 47004
            
            #set up SSH_ASKPASS for key passphrase
            Add-PasswordSetting -Pass $keypassphrase
            $o = ssh -i $user_key -p 47004 $pkuser@$server echo 2345
            Remove-PasswordSetting   
            
            Stop-SSHDTestDaemon -Port 47004
            $o | Should Be "2345"
            #check the command is run as AuthorizedPrincipalsCommandUser
            (gc $pcOutFile).Contains($ssouser) | Should Be $true          
        }
    }

}
