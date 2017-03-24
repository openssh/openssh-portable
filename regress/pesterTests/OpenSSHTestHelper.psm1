



# test environment parametes initialized with defaults
$script:OpenSSHDir = "$env:SystemDrive\OpenSSH"
$script:OpenSSHTestDir = "$env:SystemDrive\OpenSSHTests"
$script:PesterTestResultsFile = Join-Path $script:OpenSSHTestDir "PesterTestResults.xml"
$script:UnitTestResultsFile = Join-Path $script:OpenSSHTestDir "UnitTestResults.txt"
$script:TestSetupLogFile = Join-Path $script:OpenSSHTestDir "TestSetupLog.txt"

function Set-OpenSSHTestParams
{
    param
    (    
        [string] $OpenSSHDir = $script:OpenSSHDir,
        [string] $OpenSSHTestDir = $script:OpenSSHTestDir,
        [string] $PesterTestResultsFile = $script:PesterTestResultsFile,
        [string] $UnitTestResultsFile = $script:UnitTestResultsFile,
        [string] $TestSetupLogFile = $script:TestSetupLogFile
    )

    $script:OpenSSHDir = $OpenSSHDir
    $script:OpenSSHTestDir = $OpenSSHTestDir
    $script:PesterTestResultsFile = $PesterTestResultsFile
    $script:UnitTestResultsFile = $UnitTestResultsFile
    $script:TestSetupLogFile = $TestSetupLogFile
}

function Dump-OpenSSHTestParams
{
    Write-Host "OpenSSHDir:  "   $script:OpenSSHDir
    Write-Host "OpenSSHTestDir:  "  $script:OpenSSHTestDir
    Write-Host "PesterTestResultsFile: "  $script:PesterTestResultsFile
    Write-Host "UnitTestResultsFile: "  $script:UnitTestResultsFile
    Write-Host "TestSetupLogFile: " $script:TestSetupLogFile
}


<#
      .SYNOPSIS
      This function installs the tools required by our tests
      1) Pester for running the tests  
      2) sysinternals required by the tests on windows.
  #>
function Install-OpenSSHTestDependencies
{
    [CmdletBinding()]
    param ()

    # Install chocolatey
    if(-not (Get-Command "choco" -ErrorAction SilentlyContinue))
    {
        Write-Log -Message "Chocolatey not present. Installing chocolatey."
        Invoke-Expression ((new-object net.webclient).DownloadString('https://chocolatey.org/install.ps1')) 2>&1 >> $script:TestSetupLogFile
    }

    $isModuleAvailable = Get-Module 'Pester' -ListAvailable
    if (-not ($isModuleAvailable))
    {      
      Write-Log -Message "Installing Pester..." 
      choco install Pester -y --force --limitoutput 2>&1 >> $script:TestSetupLogFile
    }

    if ( -not (Test-Path "$env:ProgramData\chocolatey\lib\sysinternals\tools" ) ) {        
        Write-Log -Message "sysinternals not present. Installing sysinternals."
        choco install sysinternals -y --force --limitoutput 2>&1 >> $script:TestSetupLogFile
    }
    <#if ( (-not (Test-Path "${env:ProgramFiles(x86)}\Windows Kits\8.1\Debuggers\" )) -and (-not (Test-Path "${env:ProgramFiles(x86)}\Windows Kits\10\Debuggers\" ))) {        
        Write-Log -Message "debugger not present. Installing windbg."
        choco install windbg --force  --limitoutput -y 2>&1 >> $script:TestSetupLogFile
    }
    Install-PSCoreFromGithub
    $psCorePath = GetLocalPSCorePath
    Set-BuildVariable -Name psPath -Value $psCorePath
    #>
    Write-BuildMessage -Message "All testDependencies installed!" -Category Information
}


$testaccounts = "sshtest_ssouser", "sshtest_pubkeyuser", "sshtest_passwduser"
$testaccountPassword = "P@ssw0rd_1" | ConvertTo-SecureString -AsPlainText -Force 
    
<#
    .Synopsis
    Setup-OpenSSHTestEnvironment
#>
function Setup-OpenSSHTestEnvironment
{
    [CmdletBinding()]
    param
    (    
        [bool] $Quiet = $false
    )

    if ($Quiet -eq $false) {
        Write-Host 'WARNING: Following changes will be made to OpenSSH configuration'
        Write-Host '  - sshd_config will be backed up as sshd_config.ori'
        Write-Host '  - will be replaced with a test sshd_config'
        Write-Host '  - %user%\.ssh\known_hosts will be backed up as known_hosts.ori'
        Write-Host '  - will be replaced with a test known_hosts'
        Write-Host '  - sshd test listener will be on port 47002'
        Write-Host '  - %userprofile%\.ssh\known_hosts will be modified with test host key entry'
        Write-Host '  - test accounts - ssouser, pubkeyuser and passwduser will be added'
        Write-Host 'To cleanup - Run Cleanup-OpenSSHTestEnvironment'
    }

    if (-not(Test-Path(Join-Path $OpenSSHDir ssh.exe)))
    {
        Throw 'cannot find OpenSSH binaries under ' + $OpenSSHDir + '. Try -OpenSSHDir parameter'
    }

    try 
    {
        $sshcmd = get-command ssh.exe
    } 
    catch [System.Exception] 
    {
        Throw 'Cannot find ssh.exe. Make sure OpenSSH binary path is in %PATH%'
    }

    # TODO - ensure ssh.exe is being picked from $OpenSSHDir. Multiple versions may exist

    if (-not(Test-Path($OpenSSHTestDir))) {
        Throw $OpenSSHTestDir +' does not exist. Try setting -OpenSSHTestDir parameter'
    }

    if ((Get-ChildItem $OpenSSHTestDir).Count -eq 0) {
        Throw 'Nothing found in ' + $OpenSSHTestDir
    }

    #Backup existing OpenSSH configuration
    if (-not(Test-Path (Join-Path $OpenSSHDir sshd_config.ori))) {
        Copy-Item (Join-Path $OpenSSHDir sshd_config) (Join-Path $OpenSSHDir sshd_config.ori)
    }
    
    # copy new sshd_config
    Stop-Service sshd
    Stop-Service ssh-agent
    Copy-Item (Join-Path $OpenSSHTestDir sshd_config) (Join-Path $OpenSSHDir sshd_config)
    Copy-Item $OpenSSHTestDir\sshtest*hostkey* $OpenSSHDir
    Start-Service sshd

    #Backup existing known_hosts and replace with test version
    #TODO - account for custom known_hosts locations
    if (Test-Path (Join-Path $home .ssh\known_hosts)) {
        Copy-Item (Join-Path $home .ssh\known_hosts) (Join-Path $home .ssh\known_hosts.ori) 
    }
    Copy-Item (Join-Path $OpenSSHTestDir known_hosts) (Join-Path $home .ssh\known_hosts)

    # create test accounts
    foreach ($user in $testaccounts) {
        New-LocalUser -Name $user -Password $testaccountPassword -ErrorAction SilentlyContinue
    }

    #setup single sign on for ssouser
    #TODO - this is Windows specific. Need to be in PAL
    $ssouser = Get-LocalUser sshtest_ssouser
    $ssouserProfileRegistry = Join-Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' $ssouser.SID
    if (-not(Test-Path $ssouserProfileRegistry)) {
        #create profile
        if (-not($env:DISPLAY)) {$env:DISPLAY=1}
        $env:SSH_ASKPASS="$($env:ComSpec) /c echo P@ssw0rd_1"
        ssh -p 47002 sshtest_ssouser@localhost whoami 
        if ($env:DISPLAY -eq 1) {Remove-Item env:\DISPLAY}
        remove-item "env:SSH_ASKPASS" -ErrorAction SilentlyContinue
    }
    $ssouserProfile = (Get-ItemProperty -Path $ssouserProfileRegistry -Name 'ProfileImagePath').ProfileImagePath
    mkdir -Path (Join-Path $ssouserProfile .ssh) -ErrorAction SilentlyContinue
    Copy-Item (Join-Path $OpenSSHTestDir sshtest_userssokey_ed25519.pub) (Join-Path $ssouserProfile .ssh\authorized_keys)
    $acl = get-acl (Join-Path $ssouserProfile .ssh\authorized_keys)
    $ar = New-Object  System.Security.AccessControl.FileSystemAccessRule("NT Service\sshd", "Read", "Allow")
    $acl.SetAccessRule($ar)
    Set-Acl  (Join-Path $ssouserProfile .ssh\authorized_keys) $acl
    $ssouserpubkey = Join-Path $OpenSSHTestDir sshtest_userssokey_ed25519
    ssh-add $ssouserpubkey

    #TODO - scp tests need an admin user. This restriction should be removed
    net localgroup Administrators sshtest_ssouser /add

}


<#
    .Synopsis
    Cleanup-OpenSSHTestEnvironment
#>
function Cleanup-OpenSSHTestEnvironment
{

    [CmdletBinding()]
    param
    ()

    # .exe - Windows specific. TODO - PAL 
    if (-not(Test-Path(Join-Path $OpenSSHDir ssh.exe)))
    {
        Throw 'cannot find OpenSSH binaries under ' + $OpenSSHDir + '. Try -OpenSSHDir parameter'
    }

    #Restore sshd_config
    if (Test-Path (Join-Path $OpenSSHDir sshd_config.ori)) {
        Stop-Service sshd
        Stop-Service ssh-agent
        Copy-Item (Join-Path $OpenSSHDir sshd_config.ori) (Join-Path $OpenSSHDir sshd_config)
        Remove-Item (Join-Path $OpenSSHDir sshd_config.ori) -Force
        Remove-Item $OpenSSHDir\sshtest*hostkey* -Force
        Start-Service sshd
    }
    
    #Restore known_hosts
    if (Test-Path (Join-Path $home .ssh\known_hosts.ori)) {
        Copy-Item (Join-Path $home .ssh\known_hosts.ori) (Join-Path $home .ssh\known_hosts)
        Remove-Item  (Join-Path $home .ssh\known_hosts.ori) -Force
    }

    # delete accounts
    foreach ($user in $testaccounts) {
        Remove-LocalUser -Name $user -ErrorAction SilentlyContinue
    }
    
    # remove registered keys
    $ssouserpubkey = Join-Path $OpenSSHTestDir sshtest_userssokey_ed25519
    ssh-add -d $ssouserpubkey       

}


<#
    .Synopsis
    After build and test run completes, upload all artifacts from the build machine.
#>
function Deploy-OpenSSHTests
{
    [CmdletBinding()]
    param
    (
        [ValidateSet('Debug', 'Release', '')]
        [string]$Configuration = "",

        [ValidateSet('x86', 'x64', '')]
        [string]$NativeHostArch = ""
    )

    if (-not (Test-Path -Path $OpenSSHTestDir -PathType Container))
    {
        $null = New-Item -Path $OpenSSHTestDir -ItemType Directory -Force -ErrorAction Stop
    }

    [string] $platform = $env:PROCESSOR_ARCHITECTURE
    if(-not [String]::IsNullOrEmpty($NativeHostArch))
    {
        $folderName = $NativeHostArch
        if($NativeHostArch -eq 'x86')
        {
            $folderName = "Win32"
        }
    }
    else
    {
        if($platform -ieq "AMD64")
        {
            $folderName = "x64"
        }
        else
        {
            $folderName = "Win32"
        }
    }

    if([String]::IsNullOrEmpty($Configuration))
    {
        if( $folderName -ieq "Win32" )
        {
            $RealConfiguration = "Debug"
        }
        else
        {
            $RealConfiguration = "Release"
        }
    }
    else
    {
        $RealConfiguration = $Configuration
    }    

    [System.IO.DirectoryInfo] $repositoryRoot = Get-RepositoryRoot
    #copy all pester tests
    $sourceDir = Join-Path $repositoryRoot.FullName -ChildPath "regress\pesterTests"
    Copy-Item -Path "$sourceDir\*" -Destination $OpenSSHTestDir -Include *.ps1,*.psm1, sshd_config, known_hosts, sshtest_* -Force -ErrorAction Stop
    #copy all unit tests.
    $sourceDir = Join-Path $repositoryRoot.FullName -ChildPath "bin\$folderName\$RealConfiguration"    
    Copy-Item -Path "$sourceDir\*" -Destination "$OpenSSHTestDir\" -Container -Include unittest-* -Recurse -Force -ErrorAction Stop
    
    #restart the service to use the test copy of sshd_config
    Restart-Service sshd
}


<#
    .Synopsis
    Run OpenSSH pester tests.
#>
function Run-OpenSSHPesterTest
{
     
   # Discover all CI tests and run them.
    Push-Location $OpenSSHTestDir
    Write-Log -Message "Running OpenSSH Pester tests..."    
    $testFolders = Get-ChildItem *.tests.ps1 -Recurse -Exclude SSHDConfig.tests.ps1, SSH.Tests.ps1 | ForEach-Object{ Split-Path $_.FullName} | Sort-Object -Unique
    Invoke-Pester $testFolders -OutputFormat NUnitXml -OutputFile $PesterTestResultsFile -Tag 'CI'
    Pop-Location
}

function Check-OpenSSHPesterTestResult
{
    if (-not (Test-Path $PesterTestResultsFile))
    {
        Write-Warning "$($xml.'test-results'.failures) tests in regress\pesterTests failed"
        Write-BuildMessage -Message "Test result file $PesterTestResultsFile not found after tests." -Category Error
        Set-BuildVariable TestPassed False
    }
    $xml = [xml](Get-Content -raw $PesterTestResultsFile)
    if ([int]$xml.'test-results'.failures -gt 0) 
    {
        $errorMessage = "$($xml.'test-results'.failures) tests in regress\pesterTests failed. Detail test log is at TestResults.xml."
        Write-Warning $errorMessage
        Write-BuildMessage -Message $errorMessage -Category Error
        Set-BuildVariable TestPassed False
    }

    # Writing out warning when the $Error.Count is non-zero. Tests Should clean $Error after success.
    if ($Error.Count -gt 0) 
    {
        Write-BuildMessage -Message "Tests Should clean $Error after success." -Category Warning
        $Error| Out-File "$testInstallFolder\TestError.txt" -Append
    }
}

<#
    .Synopsis
    Run unit tests.
#>
function Run-OpenSSHUnitTest
{
     
   # Discover all CI tests and run them.
    Push-Location $OpenSSHTestDir
    Write-Log -Message "Running OpenSSH unit tests..."
    if (Test-Path $unitTestOutputFile)    
    {
        Remove-Item -Path $UnitTestResultsFile -Force -ErrorAction SilentlyContinue
    }
    $testFolders = Get-ChildItem unittest-*.exe -Recurse -Exclude unittest-sshkey.exe,unittest-kex.exe |
                 ForEach-Object{ Split-Path $_.FullName} |
                 Sort-Object -Unique
    $testfailed = $false
    if ($testFolders -ne $null)
    {
        $testFolders | % {
            Push-Location $_
            $unittestFile = "$(Split-Path $_ -Leaf).exe"
            Write-Output "Running OpenSSH unit $unittestFile ..."
            & .\$unittestFile >> $UnitTestResultsFile
            
            $errorCode = $LASTEXITCODE
            if ($errorCode -ne 0)
            {
                $testfailed = $true
                $errorMessage = "$($_.FullName) test failed for OpenSSH.`nExitCode: $errorCode. Detail test log is at UnitTestResults.txt."
                Write-Warning $errorMessage
                Write-BuildMessage -Message $errorMessage -Category Error
                Set-BuildVariable TestPassed False
            }
            Pop-Location
        }
        if(-not $testfailed)
        {
            Write-BuildMessage -Message "All Unit tests passed!" -Category Information
        }
    }
    Pop-Location
}

Export-ModuleMember -Function Set-OpenSSHTestParams, Dump-OpenSSHTestParams, Install-OpenSSHTestDependencies, Setup-OpenSSHTestEnvironment, Cleanup-OpenSSHTestEnvironment, Deploy-OpenSSHTests, Run-OpenSSHUnitTest, Run-OpenSSHPesterTest, Check-OpenSSHPesterTestResult
