param(
    [Parameter(Mandatory=$true)]
    [String]$Admin,

    [Parameter(Mandatory=$true)]
    [String]$P1,

    [Parameter(Mandatory=$true)]
    [String]$P2
)

Add-Type -AssemblyName System.Web
$Error.Clear()
$ErrorActionPreference = "Continue"

Write-Output "#########################"
Write-Output "#                       #"
Write-Output "#         Users         #"
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
$Error.Clear()
$ErrorActionPreference = "SilentlyContinue"
$DC = $false
if (Get-WmiObject -Query "select * from Win32_OperatingSystem where ProductType='2'") {
    $DC = $true
    Write-Output "$Env:ComputerName [INFO] Domain Controller"
}


if (!$DC) {
    Get-WmiObject -class win32_useraccount | ForEach-Object {net user $_.name $P1 > $null}
    Write-Output "$Env:ComputerName [INFO] User password changed"
    net user $Admin $P2 /add /y | Out-Null
    Write-Output "$Env:ComputerName [INFO] User $Admin created"
    net localgroup Administrators $Admin /add | Out-Null
    net localgroup "Remote Desktop Users" $Admin /add | Out-Null
    net localgroup "Remote Management Users" $Admin /add | Out-Null
    Write-Output "$Env:ComputerName [INFO] User $Admin added to groups"
}

if ($Error.Count -gt 0) {
    Write-Output "$Env:ComputerName [WARNING] Errors Detected"
    $Error | Out-File $env:USERPROFILE\Desktop\Users.txt -Append -Encoding utf8
}