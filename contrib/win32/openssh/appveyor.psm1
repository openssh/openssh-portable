$ErrorActionPreference = 'Stop'
Import-Module $PSScriptRoot\build.psm1
$repoRoot = Get-RepositoryRoot

# Sets a build variable
Function Set-BuildVariable
{
    param(
        [Parameter(Mandatory=$true)]
        [string]
        $Name,

        [Parameter(Mandatory=$true)]
        [string]
        $Value
    )

    if($env:AppVeyor)
    {
        Set-AppveyorBuildVariable @PSBoundParameters
    }
    else 
    {
        Set-Item env:/$name -Value $Value
    }
}

# Emulates running all of AppVeyor but locally
# should not be used on AppVeyor
function Invoke-AppVeyorFull
{
    param(
        [switch] $APPVEYOR_SCHEDULED_BUILD,
        [switch] $CleanRepo
    )
    if($CleanRepo)
    {
        Clear-PSRepo
    }

    if($env:APPVEYOR)
    {
        throw "This function is to simulate appveyor, but not to be run from appveyor!"
    }

    if($APPVEYOR_SCHEDULED_BUILD)
    {
        $env:APPVEYOR_SCHEDULED_BUILD = 'True'
    }
    try {
        #Invoke-AppVeyorInstall
        Invoke-AppVeyorBuild
        Install-OpenSSH
        Run-OpenSSHTests -uploadResults
        Publish-Artifact        
    }
    finally {
        if($APPVEYOR_SCHEDULED_BUILD -and $env:APPVEYOR_SCHEDULED_BUILD)
        {
            Remove-Item env:APPVEYOR_SCHEDULED_BUILD
        }
    }
}

# Implements the AppVeyor 'build_script' step
function Invoke-AppVeyorBuild
{  
      Start-SSHBuild -Configuration Release -NativeHostArch x64 -Verbose
      Start-SSHBuild -Configuration Debug -NativeHostArch x64 -Verbose
      Start-SSHBuild -Configuration Release -NativeHostArch x86 -Verbose
      Start-SSHBuild -Configuration Debug -NativeHostArch x86 -Verbose
}

<#
      .SYNOPSIS
      This function installs the tools required by our tests
      1) Nuget package provider - this is required so we can download from the Gallery
      2) Pester for running the tests      
  #>
function Install-TestDependencies
{
    [CmdletBinding()]
    param ()
    
    $isModuleAvailable = Get-Module 'Pester' -ListAvailable
    if (-not ($isModuleAvailable))
    {
      Write-Verbose 'Installing Pester...'
      choco install Pester -y --force
    }    
}
<#
    .Synopsis
    Deploy all required files to a location and install the binaries
#>
function Install-OpenSSH
{
    [CmdletBinding()]
    param
    (    
        [string] $OpenSSHDir = "$env:SystemDrive\OpenSSH",

        [ValidateSet('Debug', 'Release')]
        [string]$Configuration = "Debug",

        [ValidateSet('x86', 'x64', '')]
        [string]$NativeHostArch = ""
    )

    Build-Win32OpenSSHPackage @PSBoundParameters

    Push-Location $OpenSSHDir 
    &( "$OpenSSHDir\install-sshd.ps1")
    .\ssh-keygen.exe -A
    Start-Service ssh-agent
    &( "$OpenSSHDir\install-sshlsa.ps1")

    Set-Service sshd -StartupType Automatic 
    Set-Service ssh-agent -StartupType Automatic

    Pop-Location
}

<#
    .Synopsis
    uninstalled sshd and sshla
#>
function UnInstall-OpenSSH
{
    [CmdletBinding()]
    param
    (    
        [string] $OpenSSHDir = "$env:SystemDrive\OpenSSH"
    )    

    Push-Location $OpenSSHDir
    
    Stop-Service sshd    
    &( "$OpenSSHDir\uninstall-sshd.ps1")
    &( "$OpenSSHDir\uninstall-sshlsa.ps1")
    Pop-Location
}

<#
    .Synopsis
    Deploy all required files to build a package and create zip file.
#>
function Build-Win32OpenSSHPackage
{
    [CmdletBinding()]
    param
    (    
        [string] $OpenSSHDir = "$env:SystemDrive\OpenSSH",

        [ValidateSet('Debug', 'Release')]
        [string]$Configuration = "Debug",

        [ValidateSet('x86', 'x64', '')]
        [string]$NativeHostArch = ""
    )

    if (-not (Test-Path -Path $OpenSSHDir -PathType Container))
    {
        New-Item -Path $OpenSSHDir -ItemType Directory -Force -ErrorAction Stop
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

    [System.IO.DirectoryInfo] $repositoryRoot = Get-RepositoryRoot
    $sourceDir = Join-Path $repositoryRoot.FullName -ChildPath "bin\$folderName\$Configuration"
    Copy-Item -Path "$sourceDir\*" -Destination $OpenSSHDir -Include *.exe,*.dll,*.pdb -Force -ErrorAction Stop
    $sourceDir = Join-Path $repositoryRoot.FullName -ChildPath "contrib\win32\openssh"
    Copy-Item -Path "$sourceDir\*" -Destination $OpenSSHDir -Include *.ps1,sshd_config -Exclude AnalyzeCodeDiff.ps1 -Force -ErrorAction Stop    
    Copy-Item -Path "$($repositoryRoot.FullName)\sshd_config" -Destination $OpenSSHDir -Force -ErrorAction Stop

    $packageName = "rktools.2003"
    $rktoolsPath = "${env:ProgramFiles(x86)}\Windows Resource Kits\Tools\ntrights.exe"
    if (-not (Test-Path -Path $rktoolsPath))
    {
        Write-Information -MessageData "$rktoolsPath not present. Installing $rktoolsPath."        
        choco install $rktoolsPath -y --force
    }

    Copy-Item -Path $rktoolsPath -Destination $OpenSSHDir -Force -ErrorAction Stop

    $package = "$env:APPVEYOR_BUILD_FOLDER\Win32OpenSSH$Configuration$folderName.zip"
    Remove-Item -Path "$env:APPVEYOR_BUILD_FOLDER\Win32OpenSSH*.zip" -Force -ErrorAction SilentlyContinue

    Add-Type -assemblyname System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::CreateFromDirectory($OpenSSHDir, $package)    
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
        [string] $OpenSSHTestDir = "$env:SystemDrive\OpenSSH\PSTests"
    )

    if (-not (Test-Path -Path $OpenSSHTestDir -PathType Container))
    {
        New-Item -Path $OpenSSHTestDir -ItemType Directory -Force -ErrorAction Stop
    }

    [System.IO.DirectoryInfo] $repositoryRoot = Get-RepositoryRoot    
    
    $sourceDir = Join-Path $repositoryRoot.FullName -ChildPath "regress\pesterTests"
    Copy-Item -Path "$sourceDir\*" -Destination $OpenSSHTestDir -Include *.ps1,*.psm1 -Force -ErrorAction Stop
}


<#
    .Synopsis
    Adds a build log to the list of published artifacts.
    .Description
    If a build log exists, it is renamed to reflect the associated CLR runtime then added to the list of
    artifacts to publish.  If it doesn't exist, a warning is written and the file is skipped.
    The rename is needed since publishing overwrites the artifact if it already exists.
    .Parameter artifacts
    An array list to add the fully qualified build log path
    .Parameter buildLog
    The build log file produced by the build.    
#>
function Add-BuildLog
{
    param
    (
        [ValidateNotNull()]
        [System.Collections.ArrayList] $artifacts,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string] $buildLog
    )

    if (Test-Path -Path $buildLog)
    {        
        $null = $artifacts.Add($buildLog)
    }
    else
    {
        Write-Warning "Skip publishing build log. $buildLog does not exist"
    }
}

<#
    .Synopsis
    Publishes package build artifacts.    
    .Parameter artifacts
    An array list to add the fully qualified build log path
    .Parameter packageFile
    Path to the package
#>
function Add-PackageArtifact
{
    param
    (
        [ValidateNotNull()]
        [System.Collections.ArrayList] $artifacts,

        [string] $packageFile = "$env:APPVEYOR_BUILD_FOLDER\Win32OpenSSH*.zip"
    )    
    
    $files = Get-Item -Path $packageFile
    if ($files -ne $null)
    {        
        $testArtifacts | % { $artifacts.Add($_.FullName) }
    }
    else
    {
        Write-Warning "Skip publishing package artifacts. $env:APPVEYOR_BUILD_FOLDER\Win32OpenSSH*.zip does not exist"
    }
}


<#
    .Synopsis
    After build and test run completes, upload all artifacts from the build machine.
#>
function Publish-Artifact
{
    Write-Output "Publishing project artifacts"
    [System.Collections.ArrayList] $artifacts = [System.Collections.ArrayList]::new()
    Add-PackageArtifact -artifacts $artifacts -packageFile "$env:APPVEYOR_BUILD_FOLDER\Win32OpenSSH*.zip"

    # Get the build.log file for each build configuration
    [System.IO.DirectoryInfo] $repositoryRoot = Get-RepositoryRoot
    Add-BuildLog -artifacts $artifacts -buildLog (Get-BuildLogFile -root $repositoryRoot.FullName -Configuration Release -NativeHostArch x86)
    Add-BuildLog -artifacts $artifacts -buildLog (Get-BuildLogFile -root $repositoryRoot.FullName -Configuration Debug -NativeHostArch x86)
    Add-BuildLog -artifacts $artifacts -buildLog (Get-BuildLogFile -root $repositoryRoot.FullName -Configuration Release -NativeHostArch x64)
    Add-BuildLog -artifacts $artifacts -buildLog (Get-BuildLogFile -root $repositoryRoot.FullName -Configuration Debug -NativeHostArch x64)

    foreach ($artifact in $artifacts)
    {
        Write-Output "Publishing $artifact as Appveyor artifact"
        # NOTE: attempt to publish subsequent artifacts even if the current one fails
        Push-AppveyorArtifact $artifact -ErrorAction "Continue"
    }
}

function Run-OpenSSHPesterTest
{
    param($testRoot, $outputXml) 
     
   # Discover all BVT and Unit tests and run them. 
   Push-Location $testRoot 
   $testFolders = Get-ChildItem *.tests.ps1 -Recurse | ForEach-Object{ Split-Path $_.FullName} | Sort-Object -Unique 
   "<test />" | Set-content -Path $fileName -Force
   #Invoke-Pester $testFolders -OutputFormat NUnitXml -OutputFile  $outputXml 
   Pop-Location
}

<#
      .Synopsis
      Runs the tests for this repo

      .Parameter testResultsFile
      The name of the xml file to write pester results.
      The default value is '.\testResults.xml'

      .Parameter uploadResults
      Uploads the tests results.      

      .Example
      .\RunTests.ps1 
      Runs the tests and creates the default 'testResults.xml'

      .Example
      .\RunTests.ps1 -uploadResults
      Runs the tests and creates teh default 'testResults.xml' and uploads it to appveyor.

  #>
function Run-OpenSSHTests
{  
  [CmdletBinding()]
  param
  (    
      [string] $testResultsFile = "$env:SystemDrive\OpenSSH\TestResults.xml",
      [string] $testInstallFolder = "$env:SystemDrive\OpenSSH",       
      [switch] $uploadResults
  )

  Deploy-OpenSSHTests -OpenSSHTestDir $testResultsFile

  # Run all tests.
  Run-OpenSSHPesterTest -testRoot $testInstallFolder -outputXml $testResultsFile

  # UploadResults if specified.
  if ($uploadResults -and $env:APPVEYOR_JOB_ID)
  {
      (New-Object 'System.Net.WebClient').UploadFile("https://ci.appveyor.com/api/testresults/nunit/$($env:APPVEYOR_JOB_ID)", (Resolve-Path $testResultsFile))
  }

  $xml = [xml](Get-Content -raw $testResultsFile) 
  if ([int]$xml.'test-results'.failures -gt 0) 
  { 
     throw "$($xml.'test-results'.failures) tests in regress\pesterTests failed" 
  }

  # Writing out warning when the $Error.Count is non-zero. Tests Should clean $Error after success.
  if ($Error.Count -gt 0) 
  { 
      $Error| Out-File "$env:SystemDrive\OpenSSH\TestError.txt" -Append
  }
}
