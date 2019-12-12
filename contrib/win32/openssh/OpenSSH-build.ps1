[cmdletbinding()]
# PowerShell Script to clone, build and package PowerShell from specified fork and branch
param (    
    [string] $repolocation = "$pwd\openssh-portable",
    [string] $destination = "$env:WORKSPACE",
    [ValidateSet('x86', 'x64', 'arm64', 'arm')]
    [String]$NativeHostArch = 'x64',        
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = "Release",        
    [switch]$NoOpenSSL,
    [switch]$OneCore
)

try
{
    Push-location $repolocation
    Import-Module "$repolocation\contrib\win32\openssh\OpenSSHBuildHelper.psm1" -Force
    $UnitTestFolder = "Unittests-$NativeHostArch"
    $Bucket = "OpenSSH-$NativeHostArch"
    if($NativeHostArch -ieq 'x86') {
        $Bucket = "OpenSSH-Win32"
        $UnitTestFolder = "Unittests-Win32"
    }
    elseif($NativeHostArch -ieq 'x64') {
        $Bucket = "OpenSSH-Win64"
        $UnitTestFolder = "Unittests-Win64"
    }
    Write-Verbose "Start-OpenSSHBuild -NativeHostArch $NativeHostArch -Configuration $Configuration -NoOpenSSL:$NoOpenSSL -Onecore:$OneCore -Verbose " -Verbose
    Start-OpenSSHBuild -NativeHostArch $NativeHostArch -Configuration $Configuration -NoOpenSSL:$NoOpenSSL -Onecore:$OneCore -Verbose
    Write-Verbose "Start-OpenSSHPackage -NativeHostArch $NativeHostArch -Configuration $Configuration -NoOpenSSL:$NoOpenSSL -Onecore:$OneCore -DestinationPath $repolocation\$($Bucket)_symbols" -verbose
    Start-OpenSSHPackage -NativeHostArch $NativeHostArch -Configuration $Configuration -NoOpenSSL:$NoOpenSSL -Onecore:$OneCore -DestinationPath "$repolocation\$($Bucket)_symbols"
    Copy-OpenSSHUnitTests -NativeHostArch $NativeHostArch -Configuration $Configuration -DestinationPath "$repolocation\UnitTests"
    if(-not (Test-Path $destination))
    {
        New-Item -Path $destination -ItemType Directory -Force -ErrorAction Stop| Out-Null
    }
    #copy the build log
    $buildLog = Get-BuildLogFile -NativeHostArch $NativeHostArch -Configuration $Configuration -root $repolocation
    Write-Verbose "Copying $buildLog to $repolocation\$($Bucket)_symbols" -verbose
    Copy-Item -Path $buildLog -Destination "$($Bucket)_symbols\" -Force -ErrorAction SilentlyContinue

    $unitTestPaths = Get-ChildItem "$repolocation\UnitTests\*" -Directory
    Compress-Archive -path $unitTestPaths.FullName -DestinationPath "$repolocation\$($Bucket)_symbols\$UnitTestFolder" -Force
    Compress-Archive -path "$repolocation\$($Bucket)_symbols\*" -DestinationPath "$destination\$($Bucket)_symbols" -Force
}
finally
{
    Pop-Location
}

