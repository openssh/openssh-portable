$ErrorActionPreference = 'Stop'
If ($PSVersiontable.PSVersion.Major -le 2) {$PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path}
Import-Module $PSScriptRoot\OpenSSHCommonUtils.psm1 -Force
Import-Module $PSScriptRoot\OpenSSHUtils -Force

[System.IO.DirectoryInfo] $repositoryRoot = Get-RepositoryRoot
# test environment parameters initialized with defaults
$SetupTestResultsFileName = "setupTestResults.xml"
$UninstallTestResultsFileName = "UninstallTestResults.xml"
$E2ETestResultsFileName = "E2ETestResults.xml"
$UnitTestResultsFileName = "UnitTestResults.txt"
$TestSetupLogFileName = "TestSetupLog.txt"
$SSOUser = "sshtest_ssouser"
$PubKeyUser = "sshtest_pubkeyuser"
$PasswdUser = "sshtest_passwduser"
$OpenSSHTestAccountsPassword = "P@ssw0rd_1"
$OpenSSHTestAccounts = $Script:SSOUser, $Script:PubKeyUser, $Script:PasswdUser
$SSHDTestSvcName = "sshdTestSvc"

$Script:TestDataPath = "$env:SystemDrive\OpenSSHTests"
$Script:SetupTestResultsFile = Join-Path $TestDataPath $SetupTestResultsFileName
$Script:UninstallTestResultsFile = Join-Path $TestDataPath $UninstallTestResultsFileName
$Script:E2ETestResultsFile = Join-Path $TestDataPath $E2ETestResultsFileName
$Script:UnitTestResultsFile = Join-Path $TestDataPath $UnitTestResultsFileName
$Script:TestSetupLogFile = Join-Path $TestDataPath $TestSetupLogFileName
$Script:E2ETestDirectory = Join-Path $repositoryRoot.FullName -ChildPath "regress\pesterTests"
$Script:E2ETestDataDirectory = Join-Path $Script:E2ETestDirectory data
$Script:WindowsInBox = $false
$Script:NoLibreSSL = $false
$Script:EnableAppVerifier = $true
$Script:PostmortemDebugging = $false

<#
    .Synopsis
    Set-OpenSSHTestEnvironment
    TODO - split these steps into client and server side 
#>
function Set-OpenSSHTestEnvironment
{
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact="High")]
    param
    (   
        [string] $OpenSSHBinPath,
        [string] $TestDataPath = "$env:SystemDrive\OpenSSHTests",
        [Switch] $DebugMode,
        [Switch] $NoAppVerifier,
        [Switch] $PostmortemDebugging,
        [Switch] $NoLibreSSL
    )

    $params = $PSBoundParameters
    $params.Remove("DebugMode") | Out-Null
    $params.Remove("NoAppVerifier") | Out-Null
    $params.Remove("PostmortemDebugging") | Out-Null
    
    if($PSBoundParameters.ContainsKey("Verbose"))
    {
        $verboseInfo =  ($PSBoundParameters['Verbose']).IsPresent
    }

    Set-BasicTestInfo @params

    $Global:OpenSSHTestInfo.Add("Target", "localhost")                                 # test listener name
    $Global:OpenSSHTestInfo.Add("Port", "47002")                                       # test listener port
    $Global:OpenSSHTestInfo.Add("SSOUser", $SSOUser)                                   # test user with single sign on capability
    $Global:OpenSSHTestInfo.Add("PubKeyUser", $PubKeyUser)                             # test user to be used with explicit key for key auth
    $Global:OpenSSHTestInfo.Add("PasswdUser", $PasswdUser)                             # test user to be used for password auth
    $Global:OpenSSHTestInfo.Add("TestAccountPW", $OpenSSHTestAccountsPassword)         # common password for all test accounts
    $Global:OpenSSHTestInfo.Add("DebugMode", $DebugMode.IsPresent)                     # run openssh E2E in debug mode

    $Script:EnableAppVerifier = -not ($NoAppVerifier.IsPresent)
    if($Script:WindowsInBox = $true)
    {
        $Script:EnableAppVerifier = $false
    }
    $Global:OpenSSHTestInfo.Add("EnableAppVerifier", $Script:EnableAppVerifier)

    if($Script:EnableAppVerifier)
    {
        $Script:PostmortemDebugging = $PostmortemDebugging.IsPresent
    }    
    $Global:OpenSSHTestInfo.Add("PostmortemDebugging", $Script:PostmortemDebugging)

    $description = @"
WARNING: Following changes will be made to OpenSSH configuration
   - $HOME\.ssh\known_hosts will be amended with test endpoint entries
   - $HOME\.ssh\config will be amended with test endpoint entries
   - sshd test listener will be on port 47002
   - test accounts - ssouser, pubkeyuser, and passwduser will be added
   - Setup single signon for ssouser
   - To cleanup - Run Clear-OpenSSHTestEnvironment
"@  
    
    $prompt = "Are you sure you want to perform the above operations?"
    $caption = $description
    if(-not $pscmdlet.ShouldProcess($description, $prompt, $caption))
    {
        Write-Host "User decided not to make the changes."
        return
    }

    Install-OpenSSHTestDependencies

    ##### START: install sshd test service
    #delete service if exists
    if (Get-Service $SSHDTestSvcName -ErrorAction SilentlyContinue) 
    {
       Stop-Service $SSHDTestSvcName
       sc.exe delete $SSHDTestSvcName 1>$null
    }

    #prepare config directory
    $testSvcConfigDir = Join-Path $Global:OpenSSHTestInfo["TestDataPath"] "serviceconfig"
    Remove-Item $testSvcConfigDir -Force -Recurse -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Path $testSvcConfigDir
    $Global:OpenSSHTestInfo["ServiceConfigDir"] = $testSvcConfigDir
    
    #copy sshd_config
    $testSshdConfig = Join-Path $testSvcConfigDir sshd_config
    Copy-Item (Join-Path $Script:E2ETestDataDirectory sshd_config) $testSshdConfig -Force
    $con = (Get-Content $testSshdConfig | Out-String).Replace("___TEST_SERVICE_CONFIG_DIR___", $testSvcConfigDir)
    Set-Content -Path $testSshdConfig -Value "$con" -Force            
    if($DebugMode) {
        $con = (Get-Content $testSshdConfig | Out-String).Replace("#SyslogFacility AUTH","SyslogFacility LOCAL0")
        Set-Content -Path $testSshdConfig -Value "$con" -Force    
    }

    #copy sshtest keys
    Copy-Item "$($Script:E2ETestDataDirectory)\sshtest*hostkey*" $testSvcConfigDir -Force  
       
    #copy ca pubkey to ssh config path
    Copy-Item "$($Script:E2ETestDataDirectory)\sshtest_ca_userkeys.pub"  $testSvcConfigDir -Force 

    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators","FullControl","Allow")
    $acl.AddAccessRule($rule)
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule("System","FullControl","Allow")
    $acl.AddAccessRule($rule)
    $acl.SetAccessRuleProtection($true, $true)

    Get-ChildItem $testSvcConfigDir | foreach {$acl | set-acl $_.FullName}


    $SSHDTestSvcNameCmdLine = (Join-Path $script:OpenSSHBinPath sshd) + " -f " + $testSshdConfig
    New-Service -Name $SSHDTestSvcName -DisplayName "OpenSSH SSH Test Server for E2E tests" -BinaryPathName $SSHDTestSvcNameCmdLine -StartupType Manual | Out-Null
    sc.exe privs $SSHDTestSvcName SeAssignPrimaryTokenPrivilege/SeTcbPrivilege/SeBackupPrivilege/SeRestorePrivilege/SeImpersonatePrivilege

    Start-Service $SSHDTestSvcName
    ##### END: install sshd test service


    #copy ca private key to test dir
    $ca_priv_key = (Join-Path $Global:OpenSSHTestInfo["TestDataPath"] sshtest_ca_userkeys)
    Copy-Item (Join-Path $Script:E2ETestDataDirectory sshtest_ca_userkeys) $ca_priv_key -Force 
    Repair-UserSshConfigPermission -FilePath $ca_priv_key -confirm:$false
    $Global:OpenSSHTestInfo["CA_Private_Key"] = $ca_priv_key

    $sshAgentSvc = Get-service ssh-agent
    if($sshAgentSvc.StartType -eq [System.ServiceProcess.ServiceStartMode]::Disabled)
    {
        Set-service ssh-agent -StartupType Manual
    }
    Start-Service ssh-agent

    #Prepare user config - known_hosts and ssh_config
    $dotSshDirectoryPath = Join-Path $home .ssh
    if(-not (Test-Path $dotSshDirectoryPath -PathType Container))
    {
        New-Item -ItemType Directory -Path $dotSshDirectoryPath -Force -ErrorAction SilentlyContinue | out-null
    }

    $knowHostsFilePath = Join-Path $dotSshDirectoryPath known_hosts
    if (-not (Test-Path $knowHostsFilePath -PathType Leaf)) {
        Copy-Item (Join-Path $Script:E2ETestDataDirectory known_hosts) $knowHostsFilePath -Force
    }
    $con = Get-Content $knowHostsFilePath
    if (($con -eq $null) -or (-not($con.Contains("###OpenSSHE2ETests")))) {
        Get-Content (Join-Path $Script:E2ETestDataDirectory known_hosts) | Add-Content $knowHostsFilePath 
    }

    $sshConfigFilePath = Join-Path $dotSshDirectoryPath config
    if (-not (Test-Path (Join-Path $dotSshDirectoryPath config) -PathType Leaf)) {
        Copy-Item (Join-Path $Script:E2ETestDataDirectory ssh_config) $sshConfigFilePath -Force    
    }
    $con = Get-Content $sshConfigFilePath
    if (($con -eq $null) -or (-not($con.Contains("###OpenSSHE2ETests")))) {
        Get-Content (Join-Path $Script:E2ETestDataDirectory ssh_config) | Add-Content $sshConfigFilePath 
    }

    Copy-Item (Join-Path $Script:E2ETestDataDirectory ssh_config) $sshConfigFilePath -Force
    Repair-UserSshConfigPermission -FilePath $sshConfigFilePath -confirm:$false

    # create test accounts
    #TODO - this is Windows specific. Need to be in PAL
    foreach ($user in $OpenSSHTestAccounts)
    {
        try
        {
            $objUser = New-Object System.Security.Principal.NTAccount($user)
            $strSID = $objUser.Translate([System.Security.Principal.SecurityIdentifier])
        }
        catch
        {
            #only add the local user when it does not exists on the machine        
            net user $user $Script:OpenSSHTestAccountsPassword /ADD 2>&1 >> $Script:TestSetupLogFile
        }
    }

    #setup single sign on for ssouser
    $ssouserProfile = Get-LocalUserProfile -User $SSOUser
    $Global:OpenSSHTestInfo.Add("SSOUserProfile", $ssouserProfile)
    $Global:OpenSSHTestInfo.Add("PubKeyUserProfile", (Get-LocalUserProfile -User $PubKeyUser))

    New-Item -ItemType Directory -Path (Join-Path $ssouserProfile .ssh) -Force -ErrorAction SilentlyContinue  | out-null
    $authorizedKeyPath = Join-Path $ssouserProfile .ssh\authorized_keys
    $testPubKeyPath = Join-Path $Script:E2ETestDataDirectory sshtest_userssokey_ed25519.pub
    Copy-Item $testPubKeyPath $authorizedKeyPath -Force -ErrorAction SilentlyContinue
    Repair-AuthorizedKeyPermission -FilePath $authorizedKeyPath -confirm:$false 
    
    copy-item (Join-Path $Script:E2ETestDataDirectory sshtest_userssokey_ed25519) $Global:OpenSSHTestInfo["TestDataPath"]
    $testPriKeypath = Join-Path $Global:OpenSSHTestInfo["TestDataPath"] sshtest_userssokey_ed25519    
    cmd /c "ssh-add -D 2>&1 >> $Script:TestSetupLogFile"
    Repair-UserKeyPermission -FilePath $testPriKeypath -confirm:$false
    cmd /c "ssh-add $testPriKeypath 2>&1 >> $Script:TestSetupLogFile"

    #Enable AppVerifier
    if($Script:EnableAppVerifier)
    {        
        # clear all applications in application verifier first
        &  $env:windir\System32\appverif.exe -disable * -for *  | out-null
        Get-ChildItem "$($script:OpenSSHBinPath)\*.exe" | % {
            & $env:windir\System32\appverif.exe -verify $_.Name  | out-null
        }

        if($Script:PostmortemDebugging -and (Test-path $Script:WindbgPath))
        {            
            # enable Postmortem debugger            
            New-ItemProperty "HKLM:Software\Microsoft\Windows NT\CurrentVersion\AeDebug" -Name Debugger -Type String -Value "`"$Script:WindbgPath`" -p %ld -e %ld -g" -Force -ErrorAction SilentlyContinue | Out-Null
            New-ItemProperty "HKLM:Software\Microsoft\Windows NT\CurrentVersion\AeDebug" -Name Auto -Type String -Value "1" -Force -ErrorAction SilentlyContinue | Out-Null
        }
    }
}

function Set-BasicTestInfo
{
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact="High")]
    param
    (   
        [string] $OpenSSHBinPath,
        [string] $TestDataPath = "$env:SystemDrive\OpenSSHTests", 
        [Switch] $NoLibreSSL
    )

    if($Global:OpenSSHTestInfo -ne $null)
    {
        $Global:OpenSSHTestInfo.Clear()
        $Global:OpenSSHTestInfo = $null
    }
    $Script:TestDataPath = $TestDataPath;
    $Script:E2ETestResultsFile = Join-Path $TestDataPath $E2ETestResultsFileName
    $Script:SetupTestResultsFile = Join-Path $TestDataPath $SetupTestResultsFileName
    $Script:UninstallTestResultsFile = Join-Path $TestDataPath $UninstallTestResultsFileName
    $Script:UnitTestResultsFile = Join-Path $TestDataPath $UnitTestResultsFileName        
    $Script:TestSetupLogFile = Join-Path $TestDataPath $TestSetupLogFileName
    $Script:UnitTestDirectory = Get-UnitTestDirectory
    $Script:NoLibreSSL = $NoLibreSSL.IsPresent

    $Global:OpenSSHTestInfo = @{
        "TestDataPath" = $TestDataPath;                                     # openssh tests path
        "TestSetupLogFile" = $Script:TestSetupLogFile;                      # openssh test setup log file
        "E2ETestResultsFile" = $Script:E2ETestResultsFile;                  # openssh E2E test results file
        "SetupTestResultsFile" = $Script:SetupTestResultsFile;              # openssh setup test test results file
        "UninstallTestResultsFile" = $Script:UninstallTestResultsFile;      # openssh Uninstall test test results file
        "UnitTestResultsFile" = $Script:UnitTestResultsFile;                # openssh unittest test results file
        "E2ETestDirectory" = $Script:E2ETestDirectory                       # the directory of E2E tests
        "UnitTestDirectory" = $Script:UnitTestDirectory                     # the directory of unit tests
        "NoLibreSSL" = $Script:NoLibreSSL
        "WindowsInBox" = $Script:WindowsInBox
        }
    #if user does not set path, pick it up
    if([string]::IsNullOrEmpty($OpenSSHBinPath))
    {
        $sshcmd = get-command ssh.exe -ErrorAction SilentlyContinue       
        if($sshcmd -eq $null)
        {
            Throw "Cannot find ssh.exe. Please specify -OpenSSHBinPath to the OpenSSH installed location."
        }
        else
        {
            $dirToCheck = split-path $sshcmd.Path
            $description = "Pick up ssh.exe from $dirToCheck."
            $prompt = "Are you sure you want to pick up ssh.exe from $($dirToCheck)?"           
            $caption = "Found ssh.exe from $dirToCheck"
            if(-not $pscmdlet.ShouldProcess($description, $prompt, $caption))
            {
                Write-Host "User decided not to pick up ssh.exe from $dirToCheck. Please specify -OpenSSHBinPath to the OpenSSH installed location."
                return
            }
            $script:OpenSSHBinPath = $dirToCheck
        }        
    }
    else
    {
        if (-not (Test-Path (Join-Path $OpenSSHBinPath ssh.exe) -PathType Leaf))
        {
            Throw "Cannot find OpenSSH binaries under $OpenSSHBinPath. Please specify -OpenSSHBinPath to the OpenSSH installed location"
        }
        else
        {
            $script:OpenSSHBinPath = $OpenSSHBinPath
        }
    }

    $Global:OpenSSHTestInfo.Add("OpenSSHBinPath", $script:OpenSSHBinPath)
    if (-not ($env:Path.ToLower().Contains($script:OpenSSHBinPath.ToLower())))
    {
        $env:Path = "$($script:OpenSSHBinPath);$($env:path)"
    }

    $acl = get-acl (join-path $script:OpenSSHBinPath "ssh.exe")
    
    if($acl.Owner -ieq "NT SERVICE\TrustedInstaller")
    {
        $Script:WindowsInBox = $true
        $Global:OpenSSHTestInfo["WindowsInBox"]= $true
    }

    Install-OpenSSHTestDependencies -TestHarness
    if(-not (Test-path $TestDataPath -PathType Container))
    {
       New-Item -ItemType Directory -Path $TestDataPath -Force -ErrorAction SilentlyContinue | out-null
    }
}

#TODO - this is Windows specific. Need to be in PAL
function Get-LocalUserProfile
{
    param([string]$User)
    $sid = Get-UserSID -User $User
    $userProfileRegistry = Join-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" $sid
    if (-not (Test-Path $userProfileRegistry) ) {        
        #create profile
        if (-not($env:DISPLAY)) { $env:DISPLAY = 1 }
        $askpass_util = Join-Path $Script:E2ETestDirectory "utilities\askpass_util\askpass_util.exe"
        $env:SSH_ASKPASS=$askpass_util
        $env:ASKPASS_PASSWORD=$OpenSSHTestAccountsPassword
        $env:SSH_ASKPASS_REQUIRE="prefer"
        $ret = ssh -p 47002 "$User@localhost" echo %userprofile%
        if ($env:DISPLAY -eq 1) { Remove-Item env:\DISPLAY }
        Remove-item "env:SSH_ASKPASS" -ErrorAction SilentlyContinue
        Remove-item "env:ASKPASS_PASSWORD" -ErrorAction SilentlyContinue
        Remove-item "env:SSH_ASKPASS_REQUIRE" -ErrorAction SilentlyContinue
    }   
    
    (Get-ItemProperty -Path $userProfileRegistry -Name 'ProfileImagePath').ProfileImagePath    
}


<#
      .SYNOPSIS
      This function installs the tools required by our tests
      1) Pester for running the tests
      2) Windbg for postmortem debugging
#>
function Install-OpenSSHTestDependencies
{
    [CmdletBinding()]
    param ([Switch] $TestHarness)
    
    #$isOpenSSHUtilsAvailable = Get-Module 'OpenSSHUtils' -ListAvailable
    #if (-not ($isOpenSSHUtilsAvailable))
    #{      
        Write-Log -Message "Installing Module OpenSSHUtils..."
        Install-OpenSSHUtilsModule -SourceDir $PSScriptRoot
    #}
    Import-Module OpensshUtils -Force

    if($Script:WindowsInBox)
    {
        return
    }

    # Install chocolatey
    if(-not (Get-Command "choco" -ErrorAction SilentlyContinue))
    {
        Write-Log -Message "Chocolatey not present. Installing chocolatey."
        Invoke-Expression ((new-object net.webclient).DownloadString('https://chocolatey.org/install.ps1')) 2>&1 >> $Script:TestSetupLogFile
    }

    $isModuleAvailable = Get-Module 'Pester' -ListAvailable
    if (-not ($isModuleAvailable))
    {      
        Write-Log -Message "Installing Pester..." 
        choco install Pester --version 3.4.6 -y --force --limitoutput 2>&1 >> $Script:TestSetupLogFile
    }

    if($TestHarness)
    {
        return
    }

    if($Script:PostmortemDebugging -or (($OpenSSHTestInfo -ne $null) -and ($OpenSSHTestInfo["PostmortemDebugging"])))
    {
        $folderName = "x86"
        $pathroot = $env:ProgramFiles
        if($env:PROCESSOR_ARCHITECTURE -ieq "AMD64")
        {
            $folderName = "x64"
            $pathroot = ${env:ProgramFiles(x86)}
        }
        $Script:WindbgPath = "$pathroot\Windows Kits\8.1\Debuggers\$folderName\windbg.exe"
        if(-not (Test-Path $Script:WindbgPath))
        {
            $Script:WindbgPath = "$pathroot\Windows Kits\10\Debuggers\$folderName\windbg.exe"
            if(-not (Test-Path $Script:WindbgPath))
            {
                choco install windbg -y --force --limitoutput 2>&1 >> $Script:TestSetupLogFile
            }            
        }        
    }

    if(($Script:EnableAppVerifier -or (($OpenSSHTestInfo -ne $null) -and ($OpenSSHTestInfo["EnableAppVerifier"]))) -and (-not (Test-path $env:windir\System32\appverif.exe)))
    {
        choco install appverifier -y --force --limitoutput 2>&1 >> $Script:TestSetupLogFile
    }
}

function Install-OpenSSHUtilsModule
{
    [CmdletBinding()]
    param(   
        [string]$TargetDir = (Join-Path -Path $env:ProgramFiles -ChildPath "WindowsPowerShell\Modules\OpenSSHUtils"),
        [string]$SourceDir)
    
    $manifestFile = Join-Path -Path $SourceDir -ChildPath OpenSSHUtils.psd1   
    $moduleFile    = Join-Path -Path $SourceDir -ChildPath OpenSSHUtils.psm1
    $targetDirectory = $TargetDir
    $manifest = Test-ModuleManifest -Path $manifestFile -WarningAction SilentlyContinue -ErrorAction Stop
    if ($PSVersionTable.PSVersion.Major -ge 5)
    {   
        $targetDirectory = Join-Path -Path $targetDir -ChildPath $manifest.Version.ToString()
    }
    
    $modulePath = Join-Path -Path $env:ProgramFiles -ChildPath WindowsPowerShell\Modules
    if(-not (Test-Path "$targetDirectory" -PathType Container))
    {
        New-Item -ItemType Directory -Path "$targetDirectory" -Force -ErrorAction SilentlyContinue | out-null
    }
    Copy-item "$manifestFile" -Destination "$targetDirectory" -Force -ErrorAction SilentlyContinue | out-null
    Copy-item "$moduleFile" -Destination "$targetDirectory" -Force -ErrorAction SilentlyContinue | out-null
    
    if ($PSVersionTable.PSVersion.Major -lt 4)
    {
        $modulePaths = [Environment]::GetEnvironmentVariable('PSModulePath', 'Machine') -split ';'
        if ($modulePaths -notcontains $modulePath)
        {
            Write-Verbose -Message "Adding '$modulePath' to PSModulePath."

            $modulePaths = @(
                $modulePath
                $modulePaths
            )

            $newModulePath = $modulePaths -join ';'

            [Environment]::SetEnvironmentVariable('PSModulePath', $newModulePath, 'Machine')
            $env:PSModulePath += ";$modulePath"
        }
    }
}

function Uninstall-OpenSSHUtilsModule
{
    [CmdletBinding()]
    param([string]$TargetDir = (Join-Path -Path $env:ProgramFiles -ChildPath "WindowsPowerShell\Modules\OpenSSHUtils"))    
    
    if(Test-Path $TargetDir -PathType Container)
    {
        Remove-item $TargetDir -Recurse -Force -ErrorAction SilentlyContinue | out-null
    }    
}

<#
    .Synopsis
    Get-UserSID
#>
function Get-UserSID
{
    param
        (             
            [string]$Domain,            
            [string]$User
        )
    if([string]::IsNullOrEmpty($Domain))
    {
        $objUser = New-Object System.Security.Principal.NTAccount($User)        
    }
    else
    {
        $objUser = New-Object System.Security.Principal.NTAccount($Domain, $User)
    }
    $strSID = $objUser.Translate([System.Security.Principal.SecurityIdentifier])
    $strSID.Value
}

<#
    .Synopsis
    Clear-OpenSSHTestEnvironment
#>
function Clear-OpenSSHTestEnvironment
{   
    if($Global:OpenSSHTestInfo -eq $null) {
        throw "OpenSSHTestInfo is not set. Did you run Set-OpenSShTestEnvironment?"
    }

    $sshBinPath = $Global:OpenSSHTestInfo["OpenSSHBinPath"]

    # .exe - Windows specific. TODO - PAL 
    if (-not (Test-Path (Join-Path $sshBinPath ssh.exe) -PathType Leaf))
    {
        Throw "Cannot find OpenSSH binaries under $script:OpenSSHBinPath. "
    }
    
    if($Global:OpenSSHTestInfo["EnableAppVerifier"] -and (Test-path $env:windir\System32\appverif.exe))
    {
        # clear all applications in application verifier
        &  $env:windir\System32\appverif.exe -disable * -for * | out-null
    }

    if($Global:OpenSSHTestInfo["PostmortemDebugging"])
    {
        Remove-ItemProperty "HKLM:Software\Microsoft\Windows NT\CurrentVersion\AeDebug" -Name Debugger -ErrorAction SilentlyContinue -Force | Out-Null
        Remove-ItemProperty "HKLM:Software\Microsoft\Windows NT\CurrentVersion\AeDebug" -Name Auto -ErrorAction SilentlyContinue -Force | Out-Null
    }

    #delete service if exists
    if (Get-Service $SSHDTestSvcName -ErrorAction SilentlyContinue) 
    {
       Stop-Service $SSHDTestSvcName
       sc.exe delete $SSHDTestSvcName 1>$null
    }
    
    #Delete accounts
    foreach ($user in $OpenSSHTestAccounts)
    {
        net user $user /delete
    }
    
    # remove registered keys    
    cmd /c "ssh-add -d (Join-Path $Script:E2ETestDataDirectory sshtest_userssokey_ed25519) 2>&1 >> $Script:TestSetupLogFile"

    if($Global:OpenSSHTestInfo -ne $null)
    {
        $Global:OpenSSHTestInfo.Clear()
        $Global:OpenSSHTestInfo = $null
    }
    
    $isOpenSSHUtilsAvailable = Get-Module 'OpenSSHUtils' -ListAvailable
    if ($isOpenSSHUtilsAvailable)
    {      
        Write-Log -Message "Uninstalling Module OpenSSHUtils..."
        Uninstall-OpenSSHUtilsModule
    }
}

<#
    .Synopsis
    Get-UnitTestDirectory.
#>
function Get-UnitTestDirectory
{
    [CmdletBinding()]
    param
    (
        [ValidateSet('Debug', 'Release')]
        [string]$Configuration = "Release",

        [ValidateSet('x86', 'x64', '')]
        [string]$NativeHostArch = ""
    )

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
    $unitTestdir = Join-Path $repositoryRoot.FullName -ChildPath "bin\$folderName\$RealConfiguration"
    $unitTestDir
}

<#
    .Synopsis
    Run OpenSSH Setup tests.
#>
function Invoke-OpenSSHSetupTest
{    
    # Discover all CI tests and run them.
    Import-Module pester -force -global
    Push-Location $Script:E2ETestDirectory
    Write-Log -Message "Running OpenSSH Setup tests..."
    $testFolders = @(Get-ChildItem *.tests.ps1 -Recurse | ForEach-Object{ Split-Path $_.FullName} | Sort-Object -Unique)
    Invoke-Pester $testFolders -OutputFormat NUnitXml -OutputFile $Script:SetupTestResultsFile -Tag 'Setup' -PassThru
    Pop-Location
}

<#
    .Synopsis
    Run OpenSSH uninstall tests.
#>
function Invoke-OpenSSHUninstallTest
{    
    # Discover all CI tests and run them.
    Import-Module pester -force -global
    Push-Location $Script:E2ETestDirectory
    Write-Log -Message "Running OpenSSH Uninstall tests..."
    $testFolders = @(Get-ChildItem *.tests.ps1 -Recurse | ForEach-Object{ Split-Path $_.FullName} | Sort-Object -Unique)
    Invoke-Pester $testFolders -OutputFormat NUnitXml -OutputFile $Script:UninstallTestResultsFile -Tag 'Uninstall' -PassThru
    Pop-Location
}

<#
    .Synopsis
    Run OpenSSH pester tests.
#>
function Invoke-OpenSSHE2ETest
{
    [CmdletBinding()]
    param
    (
        [ValidateSet('CI', 'Scenario')]
        [string]$pri = "CI")
    # Discover all CI tests and run them.
    Import-Module pester -force -global
    Push-Location $Script:E2ETestDirectory
    Write-Log -Message "Running OpenSSH E2E tests..."
    $testFolders = @(Get-ChildItem *.tests.ps1 -Recurse | ForEach-Object{ Split-Path $_.FullName} | Sort-Object -Unique)
    Invoke-Pester $testFolders -OutputFormat NUnitXml -OutputFile $Script:E2ETestResultsFile -Tag $pri -PassThru
    Pop-Location
}

<#
    .Synopsis
    Run UNIX bash tests using CYGWIN.
#>
function Invoke-OpenSSHBashTests
{
    [string]$bashPath = [string]::Empty
    # Check for cygwin
    if (Test-Path $env:SystemDrive\cygwin\bin\sh.exe) {
        $bashPath = "$env:SystemDrive\cygwin\bin\sh.exe"
    } elseif (Test-Path $env:SystemDrive\cygwin64\bin\sh.exe) {
        $bashPath = "$env:SystemDrive\cygwin64\bin\sh.exe"
    } elseif (Test-Path $env:SystemDrive\tools\cygwin\bin\sh.exe) {
        $bashPath = "$env:SystemDrive\tools\cygwin\bin\sh.exe"
    } else {
        # Install cygwin
        Write-Host "Installing cygwin using chocolatey to $env:SystemDrive\cygwin folder"
        choco install cygwin -y --params "/InstallDir:$env:SystemDrive\cygwin\ /NoStartMenu"

        if (Test-Path $env:SystemDrive\cygwin\bin\sh.exe) {
            $bashPath = "$env:SystemDrive\cygwin\bin\sh.exe"
        } else {
            Write-Error "Failed to install cygwin to $env:SystemDrive\cygwin folder" -ErrorAction Stop
            return
        }
    }

    $bashTestDirectory = Join-Path $repositoryRoot.FullName -ChildPath "regress"

    &"$PSScriptRoot\bash_tests_iterator.ps1" -OpenSSHBinPath $Script:OpenSSHBinPath -BashTestsPath $bashTestDirectory -ShellPath $bashPath -ArtifactsDirectoryPath $bashTestDirectory
}

<#
    .Synopsis
    Run openssh unit tests.
#>
function Invoke-OpenSSHUnitTest
{     
    # Discover all CI tests and run them.
    if([string]::Isnullorempty($Script:UnitTestDirectory))
    {
        $Script:UnitTestDirectory = $OpenSSHTestInfo["UnitTestDirectory"]
    }
    Push-Location $Script:UnitTestDirectory
    Write-Log -Message "Running OpenSSH unit tests..."
    if (Test-Path $Script:UnitTestResultsFile)
    {
        $null = Remove-Item -Path $Script:UnitTestResultsFile -Force -ErrorAction SilentlyContinue
    }
    $testFolders = Get-ChildItem -filter unittest-*.exe -Recurse |
                 ForEach-Object{ Split-Path $_.FullName} |
                 Sort-Object -Unique
    $testfailed = $false
    if ($testFolders -ne $null)
    {
        $testFolders | % {
            $unittestFile = "$(Split-Path $_ -Leaf).exe"
            $unittestFilePath = join-path $_ $unittestFile
            if(Test-Path $unittestFilePath -pathtype leaf)
            {                
                $pinfo = New-Object System.Diagnostics.ProcessStartInfo
                $pinfo.FileName = "$unittestFilePath"
                $pinfo.RedirectStandardError = $true
                $pinfo.RedirectStandardOutput = $true
                $pinfo.UseShellExecute = $false
                $pinfo.WorkingDirectory = "$_"
                $p = New-Object System.Diagnostics.Process
                $p.StartInfo = $pinfo
                $p.Start() | Out-Null
                $stdout = $p.StandardOutput.ReadToEnd()
                $stderr = $p.StandardError.ReadToEnd()
                $p.WaitForExit()
                $errorCode = $p.ExitCode
                Write-Host "Running unit test: $unittestFile ..."
                if(-not [String]::IsNullOrWhiteSpace($stdout))
                {
                    Add-Content $Script:UnitTestResultsFile $stdout
                }
                if(-not [String]::IsNullOrWhiteSpace($stderr))
                {
                    Add-Content $Script:UnitTestResultsFile $stderr
                }
                if ($errorCode -ne 0)
                {
                    $testfailed = $true
                    $errorMessage = "$unittestFile failed.`nExitCode: $errorCode. Detail test log is at $($Script:UnitTestResultsFile)."
                    Write-Warning $errorMessage                         
                }
                else
                {
                    Write-Host "$unittestFile passed!"
                }
            }            
        }
    }
    Pop-Location
    $testfailed
}

<#
    Write-Log 
#>
function Write-Log
{
    param
    (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string] $Message
    )
    if(-not (Test-Path (Split-Path $Script:TestSetupLogFile) -PathType Container))
    {
        $null = New-Item -ItemType Directory -Path (Split-Path $Script:TestSetupLogFile) -Force -ErrorAction SilentlyContinue | out-null
    }
    if (-not ([string]::IsNullOrEmpty($Script:TestSetupLogFile)))
    {
        Add-Content -Path $Script:TestSetupLogFile -Value $Message
    }  
}

Export-ModuleMember -Function Set-BasicTestInfo, Set-OpenSSHTestEnvironment, Clear-OpenSSHTestEnvironment, Invoke-OpenSSHSetupTest, Invoke-OpenSSHUnitTest, Invoke-OpenSSHE2ETest, Invoke-OpenSSHUninstallTest, Invoke-OpenSSHBashTests