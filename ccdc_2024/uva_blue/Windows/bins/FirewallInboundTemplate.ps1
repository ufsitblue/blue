netsh advfirewall state allprofiles state off
netsh advfirewall firewall delete rule all
netsh 

netsh advfirewall set allprofiles logging filename %systemroot%\System32\LogFiles\Firewall\pfirewall.log
netsh advfirewall set allprofiles logging maxfilesize 16384
netsh advfirewall set allprofiles logging droppedconnections enable
netsh advfirewall set allprofiles logging allowedconnections enable

netsh advfirewall set allprofiles state on
netsh advfirewall set allprofiles firewallpolicy "blockinboundalways,allowoutbound"
netsh advfirewall firewall add rule name="RDP" dir=in action=allow program="$env:SystemRoot\system32\svchost.exe" service="TermService" enable=yes profile=any localport=3389 protocol=tcp
netsh advfirewall firewall add rule name="SSH" dir=in action=allow enable=yes profile=any localport=22 protocol=tcp
netsh advfirewall firewall add rule name="WinRM" dir=in action=allow enable=yes profile=any localport=5985 protocol=tcp remoteip=localsubnet


netsh a s a state off

netsh a s a state on

#Start-Sleep -Seconds 30

$LogIn = Get-Content "$Env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log" | Select-String -Pattern "DROP TCP" | Select-String -Pattern "RECEIVE"

for ($i = 0; $i -lt $LogIn.Length; $i++) {$LogIn[$i] = $LogIn[$i].ToString().Split(" ")[5] + ":" + $LogIn[$i].ToString().Split(" ")[7]}

$SocketsIn = $LogIn | Select-Object -Unique

$SocketsIn | ForEach-Object {
    if($PortTable[[uint16] $_.split(":")[1]] -eq $NULL) {
        netsh advfirewall firewall add rule name= "$_" dir=in action=allow protocol=TCP localport= $_.split(":")[1] enable=yes
    } else {
        $Program = $_.split(":")[1];
        $Program = ($PortTable.GetEnumerator() | Where-Object key -eq $Program | Select-Object -expand Value)
        netsh advfirewall firewall add rule name= "$_" program= $Program dir=in action=allow protocol=TCP localport= $_.split(":")[1] enable=yes
    }
}

<#
#Domain Controller
netsh a f s r n=all new e=no
netsh i ipv4 s dy tcp 49152 16384 p 
netsh i ipv4 s dy udp 49152 16384 p
netsh a s a logging droppedconnections enable
netsh a f a r n=dns dir=in act=allow localport=53 prot=udp
netsh a f a r n=kerb dir=in act=allow localport=88 prot=tcp remoteip=localsubnet
netsh a f a r n=time dir=in act=allow localport=123 prot=udp remoteip=localsubnet
netsh a f a r n=rpc dir=in act=allow localport=135 prot=tcp remoteip=localsubnet
netsh a f a r n=ldap dir=in act=allow localport=389 prot=tcp remoteip=localsubnet
netsh a f a r n=ldap dir=in act=allow localport=389 prot=udp remoteip=localsubnet
netsh a f a r n=ldaps dir=in act=allow localport=636 prot=tcp remoteip=localsubnet
netsh a f a r n=smb dir=in act=allow localport=445 prot=tcp remoteip=localsubnet
netsh a f a r n=gc dir=in act=allow localport=3268 prot=tcp remoteip=localsubnet
netsh a f a r n=gcs dir=in act=allow localport=3269 prot=tcp remoteip=localsubnet
netsh a f a r n=rdp dir=in act=allow localport=3389 prot=tcp
netsh a f a r n=winrm dir=in act=allow localport=5985 prot=tcp remoteip=localsubnet
netsh a f a r n=dynamic dir=in act=allow localport=49152-65535 prot=udp remoteip=localsubnet
netsh a f a r n=dynamic dir=in act=allow localport=49152-65535 prot=tcp remoteip=localsubnet
netsh a f a r n=dynamic dir=out act=allow localport=49152-65535 prot=udp remoteip=dns
netsh a f a r n=dynamic dir=out act=allow localport=49152-65535 prot=tcp remoteip=localsubnet
netsh a f a r n=v dir=out act=allow remoteport=8000 prot=tcp
netsh a f a r n=vs dir=out act=allow remoteport=445 prot=tcp
netsh a f a r n=w dir=out act=allow remoteport=1514-1515 prot=tcp
netsh a s a state on
netsh a s a firewallpolicy "blockinbound,blockoutbound"

#Exchange
netsh a f s r n=all new e=no
netsh i ipv4 s dy tcp 49152 16384 p 
netsh i ipv4 s dy udp 49152 16384 p
netsh a s a logging droppedconnections enable
netsh a f a r n=http dir=in act=allow localport=80 prot=tcp
netsh a f a r n=http dir=in act=allow localport=81 prot=tcp
netsh a f a r n=https dir=in act=allow localport=443 prot=tcp
netsh a f a r n=https dir=in act=allow localport=444 prot=tcp
netsh a f a r n=rdp dir=in act=allow localport=3389 prot=tcp
netsh a f a r n=winrm dir=in act=allow localport=5985 prot=tcp remoteip=localsubnet
netsh a f a r n=dynamic dir=out act=allow localport=49152-65535 prot=udp remoteip=dns
netsh a f a r n=dynamic dir=out act=allow localport=49152-65535 prot=tcp remoteip=localsubnet
netsh a f a r n=v dir=out act=allow remoteport=8000 prot=tcp
netsh a f a r n=vs dir=out act=allow remoteport=445 prot=tcp
netsh a f a r n=w dir=out act=allow remoteport=1514-1515 prot=tcp
netsh a s a state on
netsh a s a firewallpolicy "blockinbound,blockoutbound"

#netsh a f a r n=imap dir=in act=allow localport=143 prot=tcp
#netsh a f a r n=imaps dir=in act=allow localport=993 prot=tcp
#netsh a f a r n=pop3 dir=in act=allow localport=110 prot=tcp
#netsh a f a r n=pop3s dir=in act=allow localport=995 prot=tcp

#Standard Member Server
netsh a f s r n=all new e=no
netsh i ipv4 s dy tcp 49152 16384 p 
netsh i ipv4 s dy udp 49152 16384 p
netsh a s a logging droppedconnections enable
netsh a f a r n=http dir=in act=allow localport=80 prot=tcp
netsh a f a r n=smb dir=in act=allow localport=445 prot=tcp
netsh a f a r n=ftp dir=in act=allow localport=21 prot=tcp
netsh a f a r n=ftp dir=out act=allow localport=20 prot=tcp
netsh a f a r n=rdp dir=in act=allow localport=3389 prot=tcp
netsh a f a r n=winrm dir=in act=allow localport=5985 prot=tcp remoteip=localsubnet
netsh a f a r n=dynamic dir=out act=allow localport=49152-65535 prot=udp remoteip=dns
netsh a f a r n=dynamic dir=out act=allow localport=49152-65535 prot=tcp remoteip=localsubnet
netsh a f a r n=v dir=out act=allow remoteport=8000 prot=tcp
netsh a f a r n=vs dir=out act=allow remoteport=445 prot=tcp
netsh a f a r n=w dir=out act=allow remoteport=1514-1515 prot=tcp
netsh a s a state on
netsh a s a firewallpolicy "blockinbound,blockoutbound"

#>