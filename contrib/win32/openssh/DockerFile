# escape=`
#0.3.6 (no powershell 6)
#FROM travisez13/microsoft.windowsservercore.build-tools:latest
FROM balu1202/winservercore_openssh:latest

SHELL ["PowerShell.exe", "-command"]
RUN Set-ExecutionPolicy Unrestricted

COPY ./OpenSSH-build.ps1 /OpenSSH-build.ps1

ENTRYPOINT ["powershell", "-executionpolicy", "unrestricted"]
