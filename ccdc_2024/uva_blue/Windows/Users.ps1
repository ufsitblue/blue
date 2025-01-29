param(
    [Parameter(Mandatory=$true)]
    [String]$Admin
)

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
}

Add-Type -AssemblyName System.Web
$p = [System.Web.Security.Membership]::GeneratePassword(14,4)
while ($p -match '[,;:|iIlLoO0]') {
    $p = [System.Web.Security.Membership]::GeneratePassword(14,4)
}
$p = $p + "P1!"

if (!$DC) {
    $p2 = [System.Web.Security.Membership]::GeneratePassword(14,4)
    while ($p2 -match '[,;:|iIlLoO0]') {
        $p2 = [System.Web.Security.Membership]::GeneratePassword(14,4)
    }
    $p2 = $p2 + "P1!"
    Get-WmiObject -class win32_useraccount | Where-object {$_.name -ne "$Admin"} | ForEach-Object {net user $_.name $p > $null}
    net user $Admin $p2 /add /y | Out-Null
    net localgroup Administrators $Admin /add | Out-Null
    Write-Output "$Env:ComputerName [INFO] Admin account:$p2" 
    Write-Output "$Env:ComputerName [INFO] All:$p"
}

$Error | Out-File $env:USERPROFILE\Desktop\Users.txt -Append -Encoding utf8