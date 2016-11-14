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
      Start-SSHBuild -Configuration Release -NativeHostArch x64
      Start-SSHBuild -Configuration Debug -NativeHostArch x64
      Start-SSHBuild -Configuration Release -NativeHostArch x86
      Start-SSHBuild -Configuration Debug -NativeHostArch x86
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
    
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
    
    $isModuleAvailable = Get-Module 'Pester' -ListAvailable
    if (-not ($isModuleAvailable))
    {
      Write-Verbose 'Installing Pester...'
      Install-Module -Name 'Pester' -Repository PSGallery -Force -Verbose
    }    
}



<#
    .Synopsis
    After build and test run completes, upload all artifacts from the build machine.
#>
function Install-OpenSSH
{
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
    .Parameter buildRuntime
    The CLR runtime for the build.
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
    Publishes test artifacts for the build.
    .Description
    Creates a zip file containing the AppveyorDSCTests contents and publishes it.
    If the directory does not exist, a warning is written and the publish step is skipped.
    .Parameter artifacts
    An array list to add the fully qualified build log path
#>
function Add-TestArtifact
{
    param
    (
        [ValidateNotNull()]
        [System.Collections.ArrayList] $artifacts
    )
    $testInstallFolder = "$env:SystemDrive\AppveyorDSCTests"
    $testArtifacts = "$env:APPVEYOR_BUILD_FOLDER\DSCTestArchive.zip"

    if (Test-Path -Path $testInstallFolder)
    {
        Add-Type -assemblyname System.IO.Compression.FileSystem
        [System.IO.Compression.ZipFile]::CreateFromDirectory($testInstallFolder, $testArtifacts)
        $null = $artifacts.Add($testArtifacts)
    }
    else
    {
        Write-Warning "Skip publishing test artifacts. $testInstallFolder directory does not exist"
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
    #Add-TestArtifact -artifacts $artifacts

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
   Invoke-Pester $testFolders -OutputFormat NUnitXml -OutputFile  $outputXml 
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
      [string] $testResultsFile = "$env:SystemDrive\AppveyorOpenSSHTests\TestResults.xml",
      [string] $testInstallFolder = "$env:SystemDrive\AppveyorOpenSSHTests",       
      [switch] $uploadResults
  )
  # Run all tests.
  <#Run-OpenSSHPesterTest -testRoot  "$testInstallFolder\regress\pesterTests\" -outputXml $testResultsFile

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
      $Error| Out-File "$env:SystemDrive\AppveyorDSCTests\TestError.txt" -Append
  }#>
}
