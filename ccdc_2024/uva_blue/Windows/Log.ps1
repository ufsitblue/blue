$Error.Clear()
$ErrorActionPreference = "SilentlyContinue"

Write-Output "#########################"
Write-Output "#                       #"
Write-Output "#          Log          #"
Write-Output "#                       #"
Write-Output "#########################"

Write-Output "#########################"
Write-Output "#    Hostname/Domain    #"
Write-Output "#########################"
Get-WmiObject -Namespace root\cimv2 -Class Win32_ComputerSystem | Select-Object Name, Domain
Write-Output "#########################"
Write-Output "#          IP           #"
Write-Output "#########################"
Get-WmiObject Win32_NetworkAdapterConfiguration | ? {$_.IpAddress -ne $null} | % {$_.ServiceName + "`n" + $_.IPAddress + "`n"}

######### Logging#########
auditpol /set /category:* /success:enable /failure:enable | Out-Null
# Include command line in process creation events
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v "ProcessCreationIncludeCmdLine_Enabled" /t REG_DWORD /d 1 /f | Out-Null
# Powershell command transcription
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v EnableTranscripting /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v EnableInvocationHeader /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v OutputDirectory /t REG_SZ /d "C:\Windows\debug\timber" /f | Out-Null
# Powershell script block logging
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /v EnableModuleLogging /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" /v "*" /t REG_SZ /d "*" /f | Out-Null
Write-Output "$Env:ComputerName [INFO] Powershell Logging enabled"
try {
    C:\Windows\System32\inetsrv\appcmd.exe set config /section:httpLogging /dontLog:False
    Write-Output "$Env:ComputerName [INFO] IIS Logging enabled"
}
catch {
    Write-Output "$Env:ComputerName [ERROR] IIS Logging failed"
}


######### Sysmon Setup #########
if ($Env:PROCESSOR_ARCHITECTURE -eq "AMD64") {
    C:\Windows\System32\bins\Sysmon64.exe -accepteula -i C:\Windows\System32\bins\smce.xml
}
else {
    C:\Windows\System32\bins\Sysmon.exe -accepteula -i C:\Windows\System32\bins\smce.xml
}
Write-Output "$Env:ComputerName [INFO] Sysmon installed and configured"

$Error | Out-File $env:USERPROFILE\Desktop\log.txt -Append -Encoding utf8