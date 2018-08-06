[cmdletbinding(DefaultParameterSetName='Build')]
param(
    [Parameter(Mandatory,ParameterSetName='Build')]
    [String]$Name="X64",
    # full paths to files to add to container to run the build
    [Parameter(Mandatory,ParameterSetName='packageSigned')]
    [string]$BuildPath,
    [Parameter(ParameterSetName='packageSigned')]
    [string]$SignedFilesPath
)

$gitBinFullPath = (Get-Command -Name git).Source
if (-not $gitBinFullPath)
{
    throw "Git is required to proceed. Install from 'https://git-scm.com/download/win'"
}

function Get-RepoFork
{
    [CmdletBinding()]    
    param([string]$AccountURL="https://github.com/powershell", [string]$RepoFork, [string]$repoLocalPath, [string]$BranchName)
    if (Test-Path -Path $repoLocalPath -PathType Container)
    {
        Remove-Item -Path $repoLocalPath -Recurse -Force
    }    

    Write-Verbose "cloning -b $BranchName --quiet --recursive $AccountURL/$RepoFork $repoLocalPath" -Verbose
    git clone -b $BranchName --quiet --recursive $AccountURL/$RepoFork $repoLocalPath    
    
    Write-Verbose "pull latest from repo $RepoFork"
    Push-Location $repoLocalPath
    git submodule update --init --recursive --quiet
    Pop-Location
}

function Get-RepositoryRoot
{    
    $start = $currentDir = (Get-Item -Path $PSScriptRoot)
    while ($null -ne $currentDir.Parent)
    {
        $path = Join-Path -Path $currentDir.FullName -ChildPath '.git'
        if (Test-Path -Path $path)
        {
            return $currentDir
        }
        $currentDir = $currentDir.Parent
    }
    return $start
}

[System.IO.DirectoryInfo] $repositoryRoot = Get-RepositoryRoot

# Get repo root    
$OSS_OpenSSHRoot = Get-Item -Path $repositoryRoot.FullName
$gitRoot = split-path $OSS_OpenSSHRoot
$script:publishedFiles = @()
# clone psrelease.
$PSReleaseLocalPath = Join-Path -Path $gitRoot -ChildPath 'PSRelease'
Get-RepoFork -AccountURL 'https://github.com/powershell' -RepoFork 'PSRelease' -repoLocalPath $PSReleaseLocalPath -BranchName 'master'
Import-Module "$PSReleaseLocalPath\vstsBuild" -Force
Import-Module "$PSReleaseLocalPath\dockerBasedBuild" -Force
try 
{
    Clear-VstsTaskState
    switch($PSCmdlet.ParameterSetName)
    {
        'Build' {            
            Invoke-Build -RepoPath '.\' -BuildJsonPath '.\contrib\win32\openssh\build.json' -Name $Name
        }
        'packageSigned' {            
            #Publish artifacts appropriately
            if($SignedFilesPath)
            {
                Write-Verbose "SignedFilesPath: $SignedFilesPath" -Verbose
                $files = Get-ChildItem -Path $SignedFilesPath\* -File | Select-Object -ExpandProperty FullName
                #Count the remaining file not signed files.
                Get-ChildItem -Path $BuildPath\* -Recurse -File | % {
                    $src = $_.FullName                    
                    $dest = "$SignedFilesPath\$($_.Name)"
                    Write-Verbose "src: $src" -Verbose
                    Write-Verbose "dest: $dest" -Verbose
                    if (-not (Test-Path $dest))
                    {
                        $files += $_.FullName
                    }
                }
            }
            else
            {
                #did not run codesign, so publish the plain binaries
                $files = Get-ChildItem -Path $BuildPath\* -File | Select-Object -ExpandProperty FullName
            }
            $Bucket = (Split-Path $BuildPath -Leaf).Replace("_symbols", "")

            foreach($fileName in $files)
            {        
                # Only publish files once
                if($script:publishedFiles -inotcontains $fileName)
                {
                    $leafFileName = $(Split-path -Path $fileName -Leaf)                    
                    $extension = [System.IO.Path]::GetExtension($leafFileName)
                    if($extension -ieq '.pdb')
                    {
                        $folderName = "$($Bucket)_Symbols"
                        $artifactname = "$folderName-$leafFileName"
                        Write-Host "##vso[artifact.upload containerfolder=$folderName;artifactname=$artifactname]$fileName"
                    }
                    elseif($extension -ieq '.log')
                    {
                        $folderName = "$($Bucket)_Logs"
                        $artifactname = "$folderName-$leafFileName"
                        Write-Host "##vso[artifact.upload containerfolder=$folderName;artifactname=$artifactname]$fileName"
                    }
                    elseif($extension -ieq '.zip')
                    {                        
                        Write-Host "##vso[artifact.upload artifactname=$leafFileName]$fileName"
                    }
                    else
                    {
                        $artifactname = "$Bucket-$leafFileName"
                        Write-Host "##vso[artifact.upload containerfolder=$Bucket;artifactname=$artifactname]$fileName"
                    }            
                    $script:publishedFiles += $fileName
                }
            }            
        }
        default {
            throw 'Unknow parameterset passed to vstsbuild.ps1'
        }
    }
}
catch
{
    Write-VstsError -Error $_
}
finally{
    Write-VstsTaskState
    exit 0
}