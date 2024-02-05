Get-NetFirewallRule -Direction Outbound | Remove-NetFirewallRule

Set-NetFirewallProfile -All -LogBlocked True -LogMaxSizeKilobytes 16384 -LogAllowed False -LogFileName "%systemroot%\System32\LogFiles\Firewall\pfirewall.log"

Set-NetFirewallProfile -All -DefaultInboundAction Block -DefaultOutboundAction Block -Enabled True

netsh a s a state off

netsh a s a state on

Start-Sleep -Seconds 45

$LogOut = Get-Content "$Env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log" | Select-String -Pattern "DROP TCP" | Select-String -Pattern "SEND"

for ($i = 0; $i -lt $LogOut.Length; $i++) {
    $LogOut[$i] = $LogOut[$i].ToString().Split(" ")[5] + ":" + $LogOut[$i].ToString().Split(" ")[7]
}

$SocketsOut = $LogOut | Select-Object -Unique

$SocketsOut = $SocketsOut | Where-Object {$_ -like "192.168.*" -or $_ -like "10.*" -or $_ -like "172.16.*" -or $_ -like "172.17.*" -or $_ -like "172.18.*" -or $_ -like "172.19.*" -or $_ -like "172.20.*" -or $_ -like "172.21.*" -or $_ -like "172.22.*" -or $_ -like "172.23.*" -or $_ -like "172.24.*" -or $_ -like "172.25.*" -or $_ -like "172.26.*" -or $_ -like "172.27.*" -or $_ -like "172.28.*" -or $_ -like "172.29.*" -or $_ -like "172.30.*" -or $_ -like "172.31.*"}

$SocketsOut | ForEach-Object {New-NetFirewallRule -DisplayName "$_" -Direction Outbound -Action Allow -RemotePort $_.split(":")[1] -RemoteAddress $_.split(":")[0] -Protocol TCP -Enabled True -Profile Any}