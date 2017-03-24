
#covered -i -p -q -r -v -c -S -C
#todo: -F, -l and -P should be tested over the network
Describe "Tests for scp command" -Tags "CI" {
    BeforeAll {        
        $fileName1 = "test.txt"
        $fileName2 = "test2.txt"
        $SourceDirName = "SourceDir"
        $SourceDir = Join-Path ${TestDrive} $SourceDirName
        $SourceFilePath = Join-Path $SourceDir $fileName1
        $DestinationDir = Join-Path ${TestDrive} "DestDir"
        $DestinationFilePath = Join-Path $DestinationDir $fileName1        
        $NestedSourceDir= Join-Path $SourceDir "nested"
        $NestedSourceFilePath = Join-Path $NestedSourceDir $fileName2
        $null = New-Item $SourceDir -ItemType directory -Force
        $null = New-Item $NestedSourceDir -ItemType directory -Force
        $null = New-item -path $SourceFilePath -force
        $null = New-item -path $NestedSourceFilePath -force
        "Test content111" | Set-content -Path $SourceFilePath
        "Test content in nested dir" | Set-content -Path $NestedSourceFilePath
        $null = New-Item $DestinationDir -ItemType directory -Force
        
        $server = $OpenSSHTestInfo["Target"]
        $port = $OpenSSHTestInfo["Port"]
        $ssouser = $OpenSSHTestInfo["SSOUser"]
        $script:logNum = 0        

        $testData = @(
            @{
                Title = 'Simple copy local file to local file'
                Source = $SourceFilePath                   
                Destination = $DestinationFilePath
            },
            @{
                Title = 'Simple copy local file to remote file'
                Source = $SourceFilePath
                Destination = "$($ssouser)@$($server):$DestinationFilePath"                
            },
            @{
                Title = 'Simple copy remote file to local file'
                Source = "$($ssouser)@$($server):$SourceFilePath"
                Destination = $DestinationFilePath                    
            },            
            @{
                Title = 'Simple copy local file to local dir'
                Source = $SourceFilePath
                Destination = $DestinationDir
            },
            @{
                Title = 'simple copy local file to remote dir'         
                Source = $SourceFilePath
                Destination = "$($ssouser)@$($server):$DestinationDir"
            },
            @{
                Title = 'simple copy remote file to local dir'
                Source = "$($ssouser)@$($server):$SourceFilePath"
                Destination = $DestinationDir
            }
        )

        $testData1 = @(
            @{
                Title = 'copy from local dir to remote dir'
                Source = $sourceDir
                Destination = "$($ssouser)@$($server):$DestinationDir"
            },
            <#  @{
                Title = 'copy from local dir to local dir'
                Source = $sourceDir
                Destination = $DestinationDir
            },#>
            @{
                Title = 'copy from remote dir to local dir'            
                Source = "$($ssouser)@$($server):$sourceDir"
                Destination = $DestinationDir
            }
        )

        function CheckTarget {
            param([string]$target)
            if(-not (Test-path $target))
            {                
                Copy-Item .\logs\ssh-agent.log ".\logs\failedagent$script:logNum.log" -Force
                Copy-Item .\logs\sshd.log ".\logs\failedsshd$script:logNum.log" -Force
                $script:logNum++
             
                return $false
            }
            return $true
        }
    }
    AfterAll {

        Get-Item $SourceDir | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        Get-Item $DestinationDir | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    }

    BeforeAll {
        $null = New-Item $DestinationDir -ItemType directory -Force -ErrorAction SilentlyContinue
    }

    AfterEach {
        Get-ChildItem $DestinationDir -Recurse | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    }

    <#Context "SCP usage" {
        It 'SCP usage' {
            #TODO: usage output does not redirect to file
        }
    }#>       
    
    Context "SCP -i option" {
        BeforeAll {        
        }
        BeforeEach {
            if ($env:DebugMode)
            {
                Stop-Service ssh-agent -Force
                Start-Sleep 2
                # Fix this - pick up logs from ssh installation dir, not test directory
                Remove-Item .\logs\ssh-agent.log -Force -ErrorAction ignore
                Remove-Item .\logs\sshd.log -Force -ErrorAction ignore
                Start-Service sshd
            }
        }

        AfterAll {
        }
        
        It 'File copy with -i option: <Title> ' -TestCases:$testData {
            param([string]$Title, $Source, $Destination)
            scp -P $port $Source $Destination
            $LASTEXITCODE | Should Be 0

            #validate file content. DestPath is the path to the file.
            CheckTarget -target $DestinationFilePath | Should Be $true
            $equal = @(Compare-Object (Get-ChildItem -path $SourceFilePath) (Get-ChildItem -path $DestinationFilePath) -Property Name, Length).Length -eq 0            
            $equal | Should Be $true            
        }

        It 'Directory recursive copy with -i option and private key: <Title> ' -TestCases:$testData1 {
            param([string]$Title, $Source, $Destination)            

            scp -P $port -r $Source $Destination
            $LASTEXITCODE | Should Be 0
            CheckTarget -target (join-path $DestinationDir $SourceDirName) | Should Be $true
            
            $equal = @(Compare-Object (Get-Item -path $SourceDir ) (Get-Item -path (join-path $DestinationDir $SourceDirName) ) -Property Name, Length).Length -eq 0
            $equal | Should Be $true
            
            $equal = @(Compare-Object (Get-ChildItem -Recurse -path $SourceDir) (Get-ChildItem -Recurse -path (join-path $DestinationDir $SourceDirName) ) -Property Name, Length).Length -eq 0
            $equal | Should Be $true            
        }        
    }
    
    Context "SCP -p -v -c options" {
        BeforeAll {        
        }

        AfterAll {
        }        

        It 'File copy with -S option (positive)' {
            $sshcmd = (get-command ssh).Path
            scp -P $port -S $sshcmd $SourceFilePath "$($ssouser)@$($server):$DestinationFilePath"
            $LASTEXITCODE | Should Be 0
            #validate file content. DestPath is the path to the file.
            CheckTarget -target $DestinationFilePath | Should Be $true
            $equal = @(Compare-Object (Get-ChildItem -path $SourceFilePath) (Get-ChildItem -path $DestinationFilePath) -Property Name, Length).Length -eq 0
            $equal | Should Be $true
        }


        It 'File copy with -p -c option: <Title> ' -TestCases:$testData {
            param([string]$Title, $Source, $Destination)
            
            scp -P $port -p -c aes128-ctr -C $Source $Destination
            $LASTEXITCODE | Should Be 0
            #validate file content. DestPath is the path to the file.
            CheckTarget -target $DestinationFilePath | Should Be $true
            $equal = @(Compare-Object (Get-ChildItem -path $SourceFilePath) (Get-ChildItem -path $DestinationFilePath) -Property Name, Length, LastWriteTime.DateTime).Length -eq 0
            $equal | Should Be $true            
        }
                
        It 'Directory recursive copy with -r -p -c option: <Title> ' -TestCases:$testData1 {
            param([string]$Title, $Source, $Destination)                        
            
            scp -P $port -r -p -c aes128-ctr $Source $Destination
            $LASTEXITCODE | Should Be 0
            CheckTarget -target (join-path $DestinationDir $SourceDirName) | Should Be $true
            $equal = @(Compare-Object (Get-Item -path $SourceDir ) (Get-Item -path (join-path $DestinationDir $SourceDirName) ) -Property Name, Length, LastWriteTime.DateTime).Length -eq 0
            $equal | Should Be $true
                        
            $equal = @(Compare-Object (Get-ChildItem -Recurse -path $SourceDir) (Get-ChildItem -Recurse -path (join-path $DestinationDir $SourceDirName) ) -Property Name, Length, LastWriteTime.DateTime).Length -eq 0
            $equal | Should Be $true
        }
    }
   
   Context "SCP -i -C -q options" {
        BeforeAll {
        }
        
        It 'File copy with -i -C -q options: <Title> ' -TestCases:$testData{
            param([string]$Title, $Source, $Destination)

            scp -P $port  -C -q $Source $Destination
            $LASTEXITCODE | Should Be 0
            #validate file content. DestPath is the path to the file.
            CheckTarget -target $DestinationFilePath | Should Be $true
            $equal = @(Compare-Object (Get-ChildItem -path $SourceFilePath) (Get-ChildItem -path $DestinationFilePath) -Property Name, Length).Length -eq 0
            $equal | Should Be $true
        }

        It 'Directory recursive copy with -i -C -r and -q options: <Title> ' -TestCases:$testData1 {
            param([string]$Title, $Source, $Destination)               

            scp -P $port  -C -r -q $Source $Destination
            $LASTEXITCODE | Should Be 0
            CheckTarget -target (join-path $DestinationDir $SourceDirName) | Should Be $true
            $equal = @(Compare-Object (Get-Item -path $SourceDir ) (Get-Item -path (join-path $DestinationDir $SourceDirName) ) -Property Name, Length).Length -eq 0
            $equal | Should Be $true
                        
            $equal = @(Compare-Object (Get-ChildItem -Recurse -path $SourceDir) (Get-ChildItem -Recurse -path (join-path $DestinationDir $SourceDirName) ) -Property Name, Length).Length -eq 0
            $equal | Should Be $true          
        }
    }

    <#  No need to test Password auth for scp. Remove these if they are not adding any value from scp side
    Context "Password authentication" {
        BeforeAll {
            $client.AddPasswordSetting($server.localAdminPassword)
        }

        AfterAll {
            $client.CleanupPasswordSetting()
        }
        
        It 'File copy with -p options: <Title> ' -TestCases:$testData {
            param([string]$Title, $Source, $Destination)

            .\scp -p $Source $Destination
            $LASTEXITCODE | Should Be 0
            #validate file content. DestPath is the path to the file.
            CheckTarget -target $DestinationFilePath | Should Be $true
            $equal = @(Compare-Object (Get-ChildItem -path $SourceFilePath) (Get-ChildItem -path $DestinationFilePath) -Property Name, Length, LastWriteTime.DateTime).Length -eq 0
            $equal | Should Be $true
        }

        It 'Directory recursive copy with -p and -v options: <Title> ' -TestCases:$testData1 {
            param([string]$Title, $Source, $Destination)               

            .\scp -r -p $Source $Destination
            $LASTEXITCODE | Should Be 0
            CheckTarget -target (join-path $DestinationDir $SourceDirName) | Should Be $true
            $equal = @(Compare-Object (Get-Item -path $SourceDir ) (Get-Item -path (join-path $DestinationDir $SourceDirName) ) -Property Name, Length, LastWriteTime.DateTime).Length -eq 0
            $equal | Should Be $true
                        
            $equal = @(Compare-Object (Get-ChildItem -Recurse -path $SourceDir) (Get-ChildItem -Recurse -path (join-path $DestinationDir $SourceDirName) ) -Property Name, Length, LastWriteTime.DateTime).Length -eq 0
            $equal | Should Be $true          
        }
    }  
    #>
}   
