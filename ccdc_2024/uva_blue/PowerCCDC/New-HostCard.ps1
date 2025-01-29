function New-HostCard {
    param (
        [Parameter(Mandatory)]
        [String] $Board,
        [Parameter(Mandatory)]
        [String] $User,
        [Parameter(Mandatory)]
        [String] $System
    )
        if($null -eq (Get-TrelloBoard -Name $Board)) {
            Write-Host "A board with the name $BoardName does not exist, New-HostCard to create a new board" 
        }
        else {
            $password = Read-Host "Enter a new password"
            $CardTitle = "Hostname (IP) [User]"
            $CardTitle = $CardTitle -Replace "Hostname", $(hostname)
            $CardTitle = $CardTitle -Replace "User", $User
            $description = "
# System Information

## Operating System:
OS_PLACEHOLDER

## Admin User
username: $(whoami)
password: $password

## Other Details:
    DNS Servers: DNS_PLACEHOLDER"
            if ($System -eq 'Linux'){
                $IP = hostname -I
                $DNS = cat /etc/resolv.conf | grep nameserver | awk '{print $2}'
                $OperatingSystem = cat /etc/os-release  | grep PRETTY_NAME | sed 's/PRETTY_NAME=//' | sed 's/\"//g'
                $description = $description -Replace "OS_PLACEHOLDER", $OperatingSystem
                $description = $description -Replace "DNS_PLACEHOLDER", $DNS
                $CardTitle = $CardTitle -Replace "IP", $IP
                $BoxCard = New-TrelloCard -ListID (Get-TrelloList -BoardId (Get-TrelloBoard -Name $Board | Select-Object -ExpandProperty id) | Select-Object name,id | Where-Object name -eq Linux | Select-Object -expand id) -Name $CardTitle -Description $description
                New-TrelloCardChecklist -Card $BoxCard -Name users
                New-TrelloCardChecklist -Card $BoxCard -Name inbound
                New-TrelloCardChecklist -Card $BoxCard -Name outbound
                $users = cat /etc/passwd | grep -vE 'false|nologin|sync' | awk -F ":" '{print $1}'
                $outbound = netstat -tupwn | grep -E 'tcp|udp' | awk '{print $5,$7}'
                $inbound = netstat -tulpen | grep -E 'tcp|udp' | awk '{print $4,$9}'
                foreach ($user in $users){Get-TrelloCardChecklist -card $BoxCard | Where-Object {$_.name -eq 'users'} | New-TrelloCardChecklistItem -Name $user}
                foreach ($connection in $outbound){Get-TrelloCardChecklist -card $BoxCard | Where-Object {$_.name -eq 'inbound'} | New-TrelloCardChecklistItem -Name $connection}
                foreach ($connection in $inbound){Get-TrelloCardChecklist -card $BoxCard | Where-Object {$_.name -eq 'outbound'} | New-TrelloCardChecklistItem -Name $connection}

            }
            elseif ($System -eq 'Windows') {
                $IP = Get-NetIPAddress | Where-Object AddressFamily -eq 'IPv4' | Select-Object IPAddress | Where-Object IPAddress -NotLike '127.0.0.1' | Select-Object -ExpandProperty IPAddress
                $OperatingSystem = (Get-WmiObject -class Win32_OperatingSystem).Caption
                $DNSserver = Get-DnsClientServerAddress -InterfaceIndex (Get-NetAdapter | Select-Object -expand ifindex) | Where-Object ServerAddresses -inotmatch "::" | Select-Object -expand ServerAddresses
                $description = $description -Replace "OS_PLACEHOLDER", $OperatingSystem
                $description = $description -Replace "DNS_PLACEHOLDER", $DNSserver
                $CardTitle = $CardTitle -Replace "IP", $IP
                $BoxCard = New-TrelloCard -ListID (Get-TrelloList -BoardId (Get-TrelloBoard -Name $Board | Select-Object -ExpandProperty id) | Select-Object name,id | Where-Object name -eq Windows | Select-Object -expand id) -Name $CardTitle -Description $description
                
                # Manage Inventory However Windows team wants to
                # Users
                $Users = Get-LocalUser | Select-Object -expand name
                New-TrelloCardComment -Card $BoxCard -Name Users -Comment $Users

                # Network Connections
                $NetworkConnections = Get-NetTCPConnection -State Listen,Established | where-object {($_.RemotePort -ne 443) -and ($_.LocalPort -ne 5985) -and ($_.LocalAddress -inotmatch '::' )}| sort-object state,localport | Select-Object localaddress,localport,remoteaddress,remoteport,@{'Name' = 'ProcessName';'Expression'={(Get-Process -Id $_.OwningProcess).Name}}
                New-TrelloCardChecklist -Card $BoxCard -Name Connections -Item $NetworkConnections

                # Windows Features
                $Features = Get-WindowsFeature | Where-Object Installed | Select-Object -expand name
                New-TrelloCardChecklist -Card $BoxCard -Name Features -Item $Features

                # Installed Programs
                $Programs = Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall"
                $Programs = foreach ($obj in $Programs) { if (!($null -eq $obj.GetValue('DisplayName'))) { ($obj.GetValue('DisplayName') + '-' + $obj.GetValue('DisplayVersion')) }}
                New-TrelloCardChecklist -Card $BoxCard -Name Programs -Item $Programs
            }
            else {
                Write-Error 'OS needs to be either Windows or Linux'
            }
            New-TrelloCardChecklist -Card $BoxCard -Name Baselining -Item @('Inventory', 'Change Default Passwords', 'Configure Log Forwarding')
            New-TrelloCardChecklist -Card $BoxCard -name 'Password' -Item $password
    }
    return $BoxCard
}