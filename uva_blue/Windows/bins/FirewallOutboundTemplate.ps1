netsh advfirewall firewall delete rule all dir=out

netsh advfirewall set allprofiles logging filename %systemroot%\System32\LogFiles\Firewall\pfirewall.log
netsh advfirewall set allprofiles logging maxfilesize 16384
netsh advfirewall set allprofiles logging droppedconnections enable
netsh advfirewall set allprofiles logging allowedconnections enable

netsh advfirewall set allprofiles state on
netsh advfirewall set allprofiles firewallpolicy "allowinbound,blockoutboundalways"

netsh a s a state off

netsh a s a state on

Start-Sleep -Seconds 45

$LogOut = Get-Content "$Env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log" | Select-String -Pattern "DROP TCP" | Select-String -Pattern "SEND"

for ($i = 0; $i -lt $LogOut.Length; $i++) {
    $LogOut[$i] = $LogOut[$i].ToString().Split(" ")[5] + ":" + $LogOut[$i].ToString().Split(" ")[7]
}

$SocketsOut = $LogOut | Select-Object -Unique

$Program = ($PortTable.GetEnumerator() | Where-Object key -eq $Program | Select-Object -expand Value)
$SocketsOut | ForEach-Object {
    if($PortTable[[uint16] $_.split(":")[1]] -eq $NULL) {
        netsh advfirewall firewall add rule name= "$_" dir=out action=allow protocol=TCP remoteport= $_.split(":")[1] enable=yes
    } else {
        $Program = $_.split(":")[1];
        $Program = ($PortTable.GetEnumerator() | Where-Object key -eq $Program | Select-Object -expand Value)
        netsh advfirewall firewall add rule name= "$_" program= $Program dir=out action=allow protocol=TCP remoteport= $_.split(":")[1] enable=yes
    }
}