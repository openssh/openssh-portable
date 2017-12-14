﻿If ($PSVersiontable.PSVersion.Major -le 2) {$PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path}
Import-Module $PSScriptRoot\CommonUtils.psm1 -Force
$tC = 1
$tI = 0
$suite = "portfwd"

Describe "E2E scenarios for port forwarding" -Tags "CI" {
    BeforeAll {
        if($OpenSSHTestInfo -eq $null)
        {
            Throw "`$OpenSSHTestInfo is null. Please run Set-OpenSSHTestEnvironment to set test environments."
        }
        $testDir = Join-Path $OpenSSHTestInfo["TestDataPath"] $suite
        if(-not (Test-Path $testDir))
        {
            $null = New-Item $testDir -ItemType directory -Force -ErrorAction SilentlyContinue
        }
        $platform = Get-Platform
        $skip = ($platform -eq [PlatformType]::Windows) -and ($PSVersionTable.PSVersion.Major -le 2)
    }

    BeforeEach {
        $stderrFile=Join-Path $testDir "$tC.$tI.stderr.txt"
        $stdoutFile=Join-Path $testDir "$tC.$tI.stdout.txt"
        $logFile = Join-Path $testDir "$tC.$tI.log.txt"
    }        
    AfterEach {$tI++;}

    Context "$tC - Basic port forwarding scenarios"  {
        BeforeAll {$tI=1}
        AfterAll{$tC++}

        #TODO - this relies on winrm (that is windows specific)
        It "$tC.$tI - local port forwarding" -skip:$skip {
            ssh -L 5432:127.0.0.1:47001 test_target powershell.exe Test-WSMan -computer 127.0.0.1 -port 5432 | Set-Content $stdoutFile
            $stdoutFile | Should Contain "wsmid"
        }

        It "$tC.$tI - remote port forwarding" -skip:$skip {
            ssh -R 5432:127.0.0.1:47001 test_target powershell.exe Test-WSMan -computer 127.0.0.1 -port 5432  | Set-Content $stdoutFile
            $stdoutFile | Should Contain "wsmid"
        }
    }        
}
