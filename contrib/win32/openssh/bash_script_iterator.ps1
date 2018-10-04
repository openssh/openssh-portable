param (
	# Path to openssh binaries
	[Parameter(Mandatory=$true)] [string] $OpenSSHBinPath,
	# Path of regress folder which has all the bash testcases.
	[Parameter(Mandatory=$true)] [string] $BashTestsPath,
	# Path to CYGWIN / WSL.
	[Parameter(Mandatory=$true)] [string] $ShellPath,
	# Individual bash test file (Ex - connect.sh)
	[Parameter(Mandatory=$false)] [string[]] $TestFilePath,
	[Parameter(Mandatory=$false)] [string] $ArtifactsPath=".",
	[switch] $SkipCleanup,
	[switch] $SkipInstallSSHD
)

# Resolve the relative paths
$OpenSSHBinPath=resolve-path $OpenSSHBinPath -ErrorAction Stop | select -ExpandProperty Path
$BashTestsPath=resolve-path $BashTestsPath -ErrorAction Stop | select -ExpandProperty Path
$ShellPath=resolve-path $ShellPath -ErrorAction Stop | select -ExpandProperty Path
$ArtifactsPath=resolve-path $ArtifactsPath -ErrorAction Stop | select -ExpandProperty Path
if ($TestFilePath) {
	$TestFilePath=resolve-path $TestFilePath -ErrorAction Stop | select -ExpandProperty Path
	# convert to bash format
	$TestFilePath=$TestFilePath -replace "\\","/"
}

# Make sure config.h exists. It is used by bashstests (Ex - sftp-glob.sh, cfgparse.sh)
# first check in $BashTestsPath folder. If not then it's parent folder. If not then in the $OpenSSHBinPath
if(Test-Path "$BashTestsPath\config.h" -PathType Leaf) {
	$configPath="$BashTestsPath\config.h"
} elseif(Test-Path "$BashTestsPath\..\config.h" -PathType Leaf) {
	$configPath=resolve-path "$BashTestsPath\..\config.h" -ErrorAction Stop | select -ExpandProperty Path
} elseif(Test-Path "$OpenSSHBinPath\config.h" -PathType Leaf) {
	$configPath="$OpenSSHBinPath\config.h"
} else {
	Write-Error "Couldn't find config.h"
	exit
}

# store user directory
$user_pwd=pwd | select -ExpandProperty Path

# If we are using a SKU with desired OpenSSH binaries then we can skip these steps.
if(!$SkipInstallSSHD) {
	# Make sure install-sshd.ps1 exists.
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
	$out=(Get-ItemProperty -Path $registryPath -Name $dfltShell -ErrorAction SilentlyContinue)
	if($out) {
		$user_default_shell = $out.$dfltShell
		Write-Output "User configured default shell: $user_default_shell"
	}

	if (!(Test-Path $registryPath)) {
		# start and stop the sshd so that "HKLM:\Software\OpenSSH" registry path is created.
		Start-Service sshd -ErrorAction Stop
		Stop-Service sshd -ErrorAction SilentlyContinue
	}

	Set-ItemProperty -Path $registryPath -Name $dfltShell -Value $ShellPath -Force
	$out=(Get-ItemProperty -Path $registryPath -Name $dfltShell -ErrorAction SilentlyContinue)
	if($out.$dfltShell -ne $ShellPath) {
		Write-Output "Failed to set HKLM:\Software\OpenSSH\DefaultShell to $ShellPath"
		exit
	}

	# Prepend shell path to PATH. This is required to make the shell commands (like sleep, cat, etc) work properly.
	$env:TEST_SHELL_PATH=$ShellPath -replace "\\","/"
	$TEST_SHELL_DIR=split-path $ShellPath
	if(!$env:path.StartsWith($TEST_SHELL_DIR, "CurrentCultureIgnoreCase"))
	{
		$env:path=$TEST_SHELL_DIR+";"+$env:path
	}

	$BashTestsPath=$BashTestsPath -replace "\\","/"
	Push-location $BashTestsPath

	# BUILDDIR: config.h location. 
	# BUILDDIR is used by bashstests (Ex - sftp-glob.sh, cfgparse.sh)
	$BUILDDIR=resolve-path(split-path $configpath) | select -ExpandProperty Path
	$tmp=&$ShellPath -c pwd
	if ($tmp.StartsWith("/cygdrive/")) {
		$shell_drv_fmt="/cygdrive/" # "/cygdrive/" - cygwin
		$BUILDDIR=&$ShellPath -c "cygpath -u '$BUILDDIR'"
		$OpenSSHBinPath_shell_fmt=&$ShellPath -c "cygpath -u '$OpenSSHBinPath'"
		$BashTestsPath=&$ShellPath -c "cygpath -u '$BashTestsPath'"
	} elseif ($tmp.StartsWith("/mnt/")) {
		$shell_drv_fmt="/mnt/" # "/mnt/" - WSL bash
		$BUILDDIR=&$ShellPath -c "wslpath -u '$BUILDDIR'"
		$OpenSSHBinPath_shell_fmt=&$ShellPath -c "wslpath -u '$OpenSSHBinPath'"
		$BashTestsPath=&$ShellPath -c "wslpath -u '$BashTestsPath'"
	}

	#set the environment variables.
	$env:ShellPath=$ShellPath
	$env:SSH_TEST_ENVIRONMENT=1
	$env:TEST_SSH_TRACE="yes"
	$env:TEST_SHELL="/bin/sh"
	$env:TEST_SSH_PORT=22
	$env:TEST_SSH_SSH=$OpenSSHBinPath_shell_fmt+"/ssh.exe"
	$env:TEST_SSH_SSHD=$OpenSSHBinPath_shell_fmt+"/sshd.exe"
	$env:TEST_SSH_SSHAGENT=$OpenSSHBinPath_shell_fmt+"/ssh-agent.exe"
	$env:TEST_SSH_SSHADD=$OpenSSHBinPath_shell_fmt+"/ssh-add.exe"
	$env:TEST_SSH_SSHKEYGEN=$OpenSSHBinPath_shell_fmt+"/ssh-keygen.exe"
	$env:TEST_SSH_SSHKEYSCAN=$OpenSSHBinPath_shell_fmt+"/ssh-keyscan.exe"
	$env:TEST_SSH_SFTP=$OpenSSHBinPath_shell_fmt+"/sftp.exe"
	$env:TEST_SSH_SFTPSERVER=$OpenSSHBinPath_shell_fmt+"/sftp-server.exe"
	$env:TEST_SSH_SCP=$OpenSSHBinPath_shell_fmt+"/scp.exe"
	$env:BUILDDIR=$BUILDDIR
	$env:TEST_WINDOWS_SSH=1
	$user = &"$env:windir\system32\whoami.exe"
	if($user.Contains($env:COMPUTERNAME.ToLower())) {
		# for local accounts, skip COMPUTERNAME
		$user = Split-Path $user -leaf
		$env:TEST_SSH_USER=$user
	} else {
		# for domain user convert "domain\user" to "domain/user".
		$user = $user -replace "\\","/"
		$env:TEST_SSH_USER = $user
		$env:TEST_SSH_USER_DOMAIN = Split-Path $user
	}

	# output to terminal
	Write-Output "USER: $env:TEST_SSH_USER"
	Write-Output "DOMAIN: $env:TEST_SSH_USER_DOMAIN"
	Write-Output "OpenSSHBinPath: $OpenSSHBinPath_shell_fmt"
	Write-Output "BUILDDIR: $BUILDDIR"
	Write-Output "BashTestsPath: $BashTestsPath"

	# remove, create the temp test directory
	$temp_test_path="temp_test"
	$null = Remove-Item -Recurse -Force $temp_test_path -ErrorAction SilentlyContinue
	$null = New-Item -ItemType directory -Path $temp_test_path -ErrorAction Stop

	# remove the summary, output files.
	$test_summary="$ArtifactsPath\\bashtest_summary.txt"
	$test_output="$ArtifactsPath\\bashtest_output.txt"
	$null = Remove-Item -Force $test_summary -ErrorAction SilentlyContinue
	$null = Remove-Item -Force $test_output -ErrorAction SilentlyContinue
	[int]$total_tests = 0
	[int]$total_tests_passed = 0
	[int]$total_tests_failed = 0
	[string]$failed_testcases = [string]::Empty
	
	# These are the known failed testcases.
	#   agent.sh, krl.sh - User Cert authentication fails
	#   key-options.sh - pty testcases are failing (bug in conpty. conpty fails to launch cygwin bash)
	#   integrity.sh - It's dependent on regress\modpipe.exe, test is complicated. Need to debug more
	#   authinfo.sh - spawned conpty inherits all the environment variables from sshd.
	#   forward-control.sh - Need to debug more.
	[string]$known_failed_testcases = "agent.sh key-options.sh forward-control.sh integrity.sh krl.sh authinfo.sh"
	[string]$known_failed_testcases_skipped = [string]::Empty

	$start_time = (Get-Date)

	if($TestFilePath) {
		# User can specify individual test file path.
		$all_tests=$TestFilePath
	} else {
		# picking the gawk.exe from bash folder.
		# TODO - check if gawk.exe is present in WSL.
		$all_tests=gawk.exe 'sub(/.*LTESTS=/,""""){f=1} f{print $1; if (!/\\\\/) exit}' Makefile 
	}

	foreach($test_case in $all_tests) {
		if($TestFilePath) {
			$TEST=$test_case
		} else {
			if(!$test_case.Contains(".sh")) {
				$TEST=$BashTestsPath+"/"+$test_case+".sh"
			} else {
				$TEST=$BashTestsPath+"/"+$test_case
			}
		}

		$test_case_name = [System.IO.Path]::GetFileName($TEST)
		if($known_failed_testcases.Contains($test_case_name))
		{
			Write-Output "Skip the known failed test:$test_case_name"
			$known_failed_testcases_skipped = $known_failed_testcases_skipped + "$test_case_name "
		}
		else
		{
			$msg="Executing $test_case_name " +[System.DateTime]::Now
			Write-Output $msg
			&$env:ShellPath -c "/usr/bin/sh $BashTestsPath/test-exec.sh $BashTestsPath/$temp_test_path $TEST" #>$null 2>&1
			if($?)
			{
				$msg="$test_case_name PASSED " +[System.DateTime]::Now
				Write-Output $msg
				$total_tests_passed++
			}
			else
			{
				$msg="$test_case_name FAILED " +[System.DateTime]::Now
				Write-Output $msg
				$total_tests_failed++
				$failed_testcases=$failed_testcases + "$test_case_name "
			}
		}
		$total_tests++
	}

	$end_time = (Get-Date)

	# Create artifacts
	"Start time: $start_time" | Out-File -FilePath $test_summary -Append
	"End time: $end_time" | Out-File -FilePath $test_summary -Append
	"Total execution time: " + (NEW-TIMESPAN -Start $start_time -End $end_time).ToString("hh\:mm\:ss") | Out-File -FilePath $test_summary -Append
	"Tests executed: $total_tests" | Out-File -FilePath $test_summary -Append
	"Tests passed: $total_tests_passed" | Out-File -FilePath $test_summary -Append
	"Tests failed: $total_tests_failed" | Out-File -FilePath $test_summary -Append
	"Failed tests: $failed_testcases" | Out-File -FilePath $test_summary -Append
	"Skipped known failed tests: $known_failed_testcases_skipped" | Out-File -FilePath $test_summary -Append

	Write-Output "Artifacts are saved to $ArtifactsPath"

	#output the summary
	Write-Output "================================="
	cat $test_summary
	Write-Output "================================="
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
