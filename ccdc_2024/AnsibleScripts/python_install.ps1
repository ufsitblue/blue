# Open Firewall For winrm
Set-NetFirewallRule -DisplayGroup "Windows Remote Management" -Profile Any

$url = "https://www.python.org/ftp/python/3.7.0/python-3.7.0.exe"
$output = ".\python-3.7.0.exe"

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri $url -OutFile $output

#Install Python3.7 for all users
& $output /passive InstallAllUsers=1 InstallLauncherAllUsers=1 Include_test=0

# Download and install npcap.  Unfortunately, you can't install unattended.
Invoke-WebRequest -Uri "https://npcap.com/dist/npcap-1.78.exe" -OutFile "npcap.exe"
./npcap.exe
