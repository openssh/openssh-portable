param (
        [string]$sourceUrl = "https://github.com/PowerShell/libressl/releases/latest/",
        [string]$zipDir,
        [string]$destDir,
        [switch]$override
        )

If ($PSVersiontable.PSVersion.Major -le 2) {$PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path}
# Workaround that $PSScriptRoot is not support on ps version 2
if([string]::IsNullOrEmpty($zipDir))
{
    $zipDir = $PSScriptRoot
}

if([string]::IsNullOrEmpty($destDir))
{
    $destDir = $PSScriptRoot
}

if($override)
{
    Remove-Item (join-path $destDir "LibreSSL") -Recurse -Force -ErrorAction SilentlyContinue
}
elseif (Test-Path (Join-Path $destDir "LibreSSL") -PathType Container)
{
    return
}

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor `
                                              [Net.SecurityProtocolType]::Tls11 -bor `
                                              [Net.SecurityProtocolType]::Tls
    
    $request = [System.Net.WebRequest]::Create($sourceUrl)
    $request.AllowAutoRedirect = $false
    $request.Timeout = 60000; # 1 mins for the download to complete
    $response = $request.GetResponse()
    $release_url = $([String]$response.GetResponseHeader("Location")).Replace('tag','download') + '/LibreSSL.zip' 
    $zip_path = Join-Path $zipDir "libressl.zip"

    # Download libressl latest release binaries
    Remove-Item $zip_path -Force -ErrorAction SilentlyContinue
    (New-Object System.Net.WebClient).DownloadFile($release_url, $zip_path)
    if(-not (Test-Path $zip_path))
    {
        throw "failed to download ssl zip file"
    }
    
    # Expand the zip file
    Expand-Archive -Path $zip_path -DestinationPath $destDir -Force -ErrorAction SilentlyContinue -ErrorVariable e
    if($e -ne $null)
    {
        throw "Error when expand zip file"
    }
    
    Remove-Item $zip_path -Force -ErrorAction SilentlyContinue