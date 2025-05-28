$Error.Clear()
$ErrorActionPreference = "Continue"

Write-Output "#########################"
Write-Output "#                       #"
Write-Output "#          SMB          #"
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
######### SMB #########
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v SMB1 /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\System\CurrentControlSet\Services\LanManWorkstation\Parameters" /v RequireSecuritySignature /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\System\CurrentControlSet\Services\LanManWorkstation\Parameters" /v EnableSecuritySignature /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v RequireSecuritySignature /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v EnableSecuritySignature /t REG_DWORD /d 1 /f | Out-Null

reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v AutoShareServer /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v AutoShareWks /t REG_DWORD /d 0 /f | Out-Null
net share C$ /delete | Out-Null
net share ADMIN$ /delete | Out-Null
Write-Output "$Env:ComputerName SMB shares deleted and settings applied"

$Error | Out-File $env:USERPROFILE\Desktop\SMB.txt -Append -Encoding utf8