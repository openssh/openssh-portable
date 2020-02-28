param (
	# Path to openssh binaries
	[Parameter(Mandatory=$true)] [string] $OpenSSHBinPath,
	# Path of regress folder which has all the bash testcases.
	[Parameter(Mandatory=$true)] [string] $BashTestsPath,
	# Path to CYGWIN / WSL.
	[Parameter(Mandatory=$true)] [string] $ShellPath,
	# Individual bash test file (Ex - connect.sh, scp.sh)
	[Parameter(Mandatory=$false)] [string[]] $TestFilePath,
	[Parameter(Mandatory=$false)] [string] $ArtifactsDirectoryPath=".",
	[switch] $SkipCleanup,
	[switch] $SkipInstallSSHD
)

$ErrorActionPreference = 'Continue'

# Resolve the relative paths
$OpenSSHBinPath = Resolve-Path $OpenSSHBinPath -ErrorAction Stop | select -ExpandProperty Path
$BashTestsPath = Resolve-Path $BashTestsPath -ErrorAction Stop | select -ExpandProperty Path
$ShellPath = Resolve-Path $ShellPath -ErrorAction Stop | select -ExpandProperty Path
$ArtifactsDirectoryPath = Resolve-Path $ArtifactsDirectoryPath -ErrorAction Stop | select -ExpandProperty Path
if ($TestFilePath) {
	$TestFilePath = Resolve-Path $TestFilePath -ErrorAction Stop | select -ExpandProperty Path
	# convert to bash format
	$TestFilePath = $TestFilePath -replace "\\","/"
}

# Make sure config.h exists. It is used in some bashstests (Ex - sftp-glob.sh, cfgparse.sh)
# first check in $BashTestsPath folder. If not then it's parent folder. If not then in the $OpenSSHBinPath
if(Test-Path "$BashTestsPath\config.h" -PathType Leaf) {
	$configPath = "$BashTestsPath\config.h"
} elseif(Test-Path "$BashTestsPath\..\config.h" -PathType Leaf) {
	$configPath = Resolve-Path "$BashTestsPath\..\config.h" -ErrorAction Stop | select -ExpandProperty Path
} elseif(Test-Path "$OpenSSHBinPath\config.h" -PathType Leaf) {
	$configPath = "$OpenSSHBinPath\config.h"
} else {
	Write-Error "Couldn't find config.h"
	exit
}

$user_pwd = pwd | select -ExpandProperty Path

# If we are using a SKU with desired OpenSSH binaries then we can skip these steps.
if(!$SkipInstallSSHD) {
	# Make sure install-sshd.ps1 exists.
	# This is required only for ssh-agent related bash tests.
	if(!(Test-Path "$PSScriptRoot\install-sshd.ps1" -PathType Leaf)) {
		Write-Error "$PSScriptRoot\install-sshd.ps1 doesn't exists"
		exit
	}

	# Make sure uninstall-sshd.ps1 exists.
	if(!(Test-Path "$PSScriptRoot\uninstall-sshd.ps1" -PathType Leaf)) {
		Write-Error "$PSScriptRoot\uninstall-sshd.ps1 doesn't exists"
		exit
	}

	#copy to binary folder and execute install-sshd.ps1
	Copy-Item $PSScriptRoot\install-sshd.ps1 -Force $OpenSSHBinPath
	Copy-Item $PSScriptRoot\uninstall-sshd.ps1 -Force $OpenSSHBinPath

	# We need ssh-agent to be installed as service to run some bash tests.
	& "$OpenSSHBinPath\install-sshd.ps1"
}

try
{
	# set the default shell
	$registryPath = "HKLM:\Software\OpenSSH"
	$dfltShell = "DefaultShell"
	# Fetch the user configured default shell.
	$out = (Get-ItemProperty -Path $registryPath -Name $dfltShell -ErrorAction SilentlyContinue)
	if ($out) {
		$user_default_shell = $out.$dfltShell
		Write-Output "User configured default shell: $user_default_shell"
	}

	if ($user_default_shell -ne $ShellPath)
	{
		if (!(Test-Path $registryPath)) {
			# start and stop the sshd so that "HKLM:\Software\OpenSSH" registry path is created.
			Start-Service sshd -ErrorAction Stop
			Stop-Service sshd -ErrorAction SilentlyContinue
		}

		Set-ItemProperty -Path $registryPath -Name $dfltShell -Value $ShellPath -Force
		$out = (Get-ItemProperty -Path $registryPath -Name $dfltShell -ErrorAction SilentlyContinue)
		if ($out.$dfltShell -ne $ShellPath) {
			Write-Output "Failed to set HKLM:\Software\OpenSSH\DefaultShell to $ShellPath"
			exit
		}

		Write-Output "Successfully set the default shell (HKLM:\Software\OpenSSH\DefaultShell) to $ShellPath"
	}

	# Prepend shell path to PATH. This is required to make the shell commands (like sleep, cat, etc) work properly.
	$env:TEST_SHELL_PATH = $ShellPath -replace "\\","/"
	$TEST_SHELL_DIR = split-path $ShellPath
	if(!$env:path.StartsWith($TEST_SHELL_DIR, "CurrentCultureIgnoreCase"))
	{
		$env:path = $TEST_SHELL_DIR + ";" + $env:path
	}

	$BashTestsPath = $BashTestsPath -replace "\\","/"
	Push-location $BashTestsPath

	# BUILDDIR: config.h location. 
	# BUILDDIR is used by bashstests (Ex - sftp-glob.sh, cfgparse.sh)
	$BUILDDIR = Resolve-Path(split-path $configpath) | select -ExpandProperty Path
	$tmp = &$ShellPath -c pwd
	if ($tmp.StartsWith("/cygdrive/")) {
		$shell_drv_fmt = "/cygdrive/" # cygwin
		$BUILDDIR = &$ShellPath -c "cygpath -u '$BUILDDIR'"
		$OpenSSHBinPath_shell_fmt=&$ShellPath -c "cygpath -u '$OpenSSHBinPath'"
		$BashTestsPath = &$ShellPath -c "cygpath -u '$BashTestsPath'"
	} elseif ($tmp.StartsWith("/mnt/")) {
		$shell_drv_fmt = "/mnt/" # WSL bash
		$BUILDDIR = &$ShellPath -c "wslpath -u '$BUILDDIR'"
		$OpenSSHBinPath_shell_fmt=&$ShellPath -c "wslpath -u '$OpenSSHBinPath'"
		$BashTestsPath = &$ShellPath -c "wslpath -u '$BashTestsPath'"
	}

	#set the environment variables.
	$env:ShellPath = $ShellPath
	$env:SSH_TEST_ENVIRONMENT = 1
	$env:TEST_SSH_TRACE = "yes"
	$env:TEST_SHELL = "/bin/sh"
	$env:TEST_SSH_PORT = 22
	$env:TEST_SSH_SSH = $OpenSSHBinPath_shell_fmt+"/ssh.exe"
	$env:TEST_SSH_SSHD = $OpenSSHBinPath_shell_fmt+"/sshd.exe"
	$env:TEST_SSH_SSHAGENT = $OpenSSHBinPath_shell_fmt+"/ssh-agent.exe"
	$env:TEST_SSH_SSHADD = $OpenSSHBinPath_shell_fmt+"/ssh-add.exe"
	$env:TEST_SSH_SSHKEYGEN = $OpenSSHBinPath_shell_fmt+"/ssh-keygen.exe"
	$env:TEST_SSH_SSHKEYSCAN = $OpenSSHBinPath_shell_fmt+"/ssh-keyscan.exe"
	$env:TEST_SSH_SFTP = $OpenSSHBinPath_shell_fmt+"/sftp.exe"
	$env:TEST_SSH_SFTPSERVER = $OpenSSHBinPath_shell_fmt+"/sftp-server.exe"
	$env:TEST_SSH_SCP = $OpenSSHBinPath_shell_fmt+"/scp.exe"
	$env:BUILDDIR = $BUILDDIR
	$env:TEST_WINDOWS_SSH = 1
	$user = &"$env:windir\system32\whoami.exe"
	if($user.Contains($env:COMPUTERNAME.ToLower())) {
		# for local accounts, skip COMPUTERNAME
		$user = Split-Path $user -leaf
		$env:TEST_SSH_USER = $user
	} else {
		# for domain user convert "domain\user" to "domain/user".
		$user = $user -replace "\\","/"
		$env:TEST_SSH_USER = $user
		$env:TEST_SSH_USER_DOMAIN = Split-Path $user
	}

	Write-Output "USER: $env:TEST_SSH_USER"
	Write-Output "DOMAIN: $env:TEST_SSH_USER_DOMAIN"
	Write-Output "OpenSSHBinPath: $OpenSSHBinPath_shell_fmt"
	Write-Output "BUILDDIR: $BUILDDIR"
	Write-Output "BashTestsPath: $BashTestsPath"

	# remove, create the temp test directory
	$temp_test_path = "temp_test"
	$null = Remove-Item -Recurse -Force $temp_test_path -ErrorAction SilentlyContinue
	$null = New-Item -ItemType directory -Path $temp_test_path -Force -ErrorAction Stop

	# remove the summary, output files.
	$bash_test_summary = "$ArtifactsDirectoryPath\bash_tests_summary.txt"
	$bash_test_log_file = "$ArtifactsDirectoryPath\bash_tests_output.log"
	$null = Remove-Item -Force $bash_test_summary -ErrorAction SilentlyContinue
	$null = Remove-Item -Force $bash_test_log_file -ErrorAction SilentlyContinue
	[int]$total_tests = 0
	[int]$total_tests_passed = 0
	[int]$total_tests_failed = 0
	[string]$failed_testcases = [string]::Empty
	
	# These are the known failed testcases.
	$known_failed_testcases = @("agent.sh", "key-options.sh", "forward-control.sh", "integrity.sh", "krl.sh", "cert-hostkey.sh", "cert-userkey.sh")
	$known_failed_testcases_skipped = @()

	$start_time = (Get-Date)

	if($TestFilePath) {
		# User can specify individual test file path.
		$all_tests = $TestFilePath
	} else {
		# picking the gawk.exe from bash folder.
		# TODO - check if gawk.exe is present in WSL.
		$all_tests = gawk.exe 'sub(/.*LTESTS=/,""""){f=1} f{print $1; if (!/\\\\/) exit}' Makefile
	}

	Write-Output ""

	foreach ($test_file in $all_tests) {
		if ($TestFilePath) {
			$TEST = $test_file
		} else {
			if (!$test_file.Contains(".sh")) {
				$TEST = $BashTestsPath + "/" + $test_file + ".sh"
			} else {
				$TEST = $BashTestsPath + "/" + $test_file
			}
		}

		$test_file_name = [System.IO.Path]::GetFileName($TEST)
		if ($known_failed_testcases.Contains($test_file_name))
		{
			Write-Output "Skip the known failed test:$test_file_name [$($all_tests.IndexOf($test_file) + 1) of $($all_tests.count)]"
			$known_failed_testcases_skipped +=  "$test_file_name"
		}
		else
		{
			$msg = "Run $test_file_name [$($all_tests.IndexOf($test_file) + 1) of $($all_tests.count)] " + [System.DateTime]::Now
			Write-Output $msg | Tee-Object -FilePath $bash_test_log_file -Append -ErrorAction Stop

			&$env:ShellPath -c "/usr/bin/sh $BashTestsPath/test-exec.sh $BashTestsPath/$temp_test_path $TEST 2>&1" | Out-File -FilePath $bash_test_log_file -Append -ErrorAction Stop
			if ($?)
			{
				$msg = "$test_file_name PASSED " + [System.DateTime]::Now
				Write-Output $msg | Tee-Object -FilePath $bash_test_log_file -Append -ErrorAction Stop
				$total_tests_passed++
			}
			else
			{
				$msg = "$test_file_name FAILED " + [System.DateTime]::Now
				Write-Output $msg | Tee-Object -FilePath $bash_test_log_file -Append -ErrorAction Stop
				$total_tests_failed++
				$failed_testcases = $failed_testcases + "$test_file_name "
			}
		}

		$total_tests++
	}

	$end_time = (Get-Date)

	# Create artifacts
	$Global:bash_tests_summary = [ordered]@{
		"StartTime" = $start_time.ToString();
		"EndTime" = $end_time.ToString();
		"TotalExecutionTime" = (NEW-TIMESPAN -Start $start_time -End $end_time).ToString("hh\:mm\:ss");
		"TotalBashTests" = $total_tests;
		"TotalBashTestsPassed" = $total_tests_passed;
		"TotalBashTestsFailed" = $total_tests_failed;
		"TotalBashTestsSkipped" = $known_failed_testcases_skipped.Count;
		"FailedBashTests" = $failed_testcases;
		"SkippedBashTests" = $known_failed_testcases_skipped -join ', ';
		"BashTestSummaryFile" = $bash_test_summary
		"BashTestLogFile"  = $bash_test_log_file
	}

	$Global:bash_tests_summary | ConvertTo-Json | Out-File -FilePath $bash_test_summary

	#output the summary
	Write-Output "`n============================================"
	Get-Content -Raw $bash_test_summary
	Write-Output "============================================`n"
}
finally
{
	# remove temp test directory
	if (!$SkipCleanup)
	{
		# remove temp test folder
		&$ShellPath -c "rm -rf $BashTestsPath/temp_test"

		if(!$SkipInstallSSHD) {
			# Uninstall the sshd, ssh-agent service
			& "$PSScriptRoot\uninstall-sshd.ps1"
		}

		# Remove the test environment variable
		Remove-Item ENV:\SSH_TEST_ENVIRONMENT

		# Revert to user configured default shell.
		if($user_default_shell) {
			Set-ItemProperty -Path $registryPath -Name $dfltShell -Value $user_default_shell -Force
			$out=(Get-ItemProperty -Path $registryPath -Name $dfltShell -ErrorAction SilentlyContinue)
			if($out.$dfltShell -eq $user_default_shell) {
				Write-Output "Reverted user configured default shell to $user_default_shell"
			} else {
				Write-Output "Failed to set HKLM:\Software\OpenSSH\DefaultShell to $user_default_shell"
			}
		} else {
			Remove-ItemProperty -Path $registryPath -Name $dfltShell -ErrorAction SilentlyContinue
		}
	}

	Push-location $user_pwd
}
