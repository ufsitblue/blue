$Error.Clear()
$ErrorActionPreference = "SilentlyContinue"

Write-Output "#########################"
Write-Output "#                       #"
Write-Output "#          Gpo          #"
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

(get-gpo "Default Domain Policy").GpoStatus = "AllSettingsDisabled"
(get-gpo "Default Domain Controllers Policy").GpoStatus = "AllSettingsDisabled"
Write-Output "$Env:ComputerName [INFO] Set GPOs"