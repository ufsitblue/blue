$Error.Clear()
$ErrorActionPreference = "SilentlyContinue"

Write-Output "#########################"
Write-Output "#                       #"
Write-Output "#          Exec         #"
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

if ($Env:PROCESSOR_ARCHITECTURE -eq "AMD64") {
    Start-Process powershell -ArgumentList ""
    Start-Process powershell -ArgumentList ""
}
else {
    Start-Process powershell -ArgumentList ""
    Start-Process powershell -ArgumentList ""
}
Write-Output "$Env:ComputerName [INFO] Executed "