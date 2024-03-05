# Variables
$dc_ips = @()
$domain_ips = @()
$team_ips = @()
$dc_ports_tcp = @("53", "88", "135", "389", "445", "464", "636", "3268", "3269", "49152-65535")
$dc_ports_udp = @("53", "88", "123", "389", "464")

do {
    $ip = Read-Host "Enter a team IP address (or type 'done' to finish)"
    if ($ip -ne "done") {
        $team_ips += $ip
    }
} until ($ip -eq "done")

do {
    $ip = Read-Host "Enter Domain Controller ip (or type 'done' to finish)"
    if ($ip -ne "done") {
        $dc_ips += $ip
    }
} until ($ip -eq "done")

$domain_controller = Read-Host "Enter 'yes' if this machine is a Domain Controller"
if ($domain_controller -eq "yes") {
    do {
        $ip = Read-Host "Enter an ip address of a machine in the domain that isn't a DC (or 'done' to finish)"
        if ($ip -ne "done") {
            $domain_ips += $ip
        }
    } until ($ip -eq "done")
}

# Disable all firewalls
Set-NetFirewallProfile -All -Enabled False

# Back up and delete original firewall rules
netsh advfirewall export C:\backup.wfw
Get-NetFirewallRule | Remove-NetFirewallRule -Confirm:$false

# Add ICMP rule
New-NetFirewallRule -DisplayName "Allow ping" -Description "Allow icmp for network debugging" -Direction Inbound -Protocol ICMPv4 -Action Allow -Group "Standard"

# Add localhost rules
New-NetFirewallRule -DisplayName "Localhost in" -Description "Allow localhost into the network" -Direction Inbound -localAddress 127.0.0.0/8 -RemoteAddress 127.0.0.0/8 -Action Allow -Group "Standard"
New-NetFirewallRule -DisplayName "Localhost out" -Description "Allow localhost into the network" -Direction Outbound -localAddress 127.0.0.0/8 -RemoteAddress 127.0.0.0/8 -Action Allow -Group "Standard"

# Add RDP rules
New-NetFirewallRule -DisplayName "RDP from team" -Description "Allow RDP from team into network" -Direction Inbound -Protocol TCP -LocalPort 3389 -RemoteAddress $team_ips -Action Allow -Group "Blackout"
New-NetFirewallRule -DisplayName "RDP to team" -Description "Allow RDP from team into network" -Direction Outbound -Protocol TCP -LocalPort 3389 -RemoteAddress $team_ips -Action Allow -Group "Blackout"

# Add winrm rules
New-NetFirewallRule -DisplayName "winrm from team" -Description "Allow winrm from team into network" -Direction Inbound -Protocol TCP -LocalPort 5985 -RemoteAddress $team_ips -Action Allow -Group "Standard"
New-NetFirewallRule -DisplayName "winrm to team" -Description "Allow winrm from team into network" -Direction Outbound -Protocol TCP -LocalPort 5985 -RemoteAddress $team_ips -Action Allow -Group "Standard"

# Add internet connection rules
New-NetFirewallRule -DisplayName "Http/s traffic out" -Description "Allow http/s traffic out of network" -Direction Outbound -Protocol TCP -RemotePort 80,443 -Action Allow -Group "Internet"
New-NetFirewallRule -DisplayName "DNS traffic out" -Description "Allow DNS traffic out of network" -Direction Outbound -Protocol UDP -RemotePort 53 -Action Allow -Group "Internet"


if ($domain_controller -eq "yes") {
    # Allow DCs to communicate if there are multiple
    if ($dc_ips.Count > 1){
      New-NetFirewallRule -DisplayName "DC to DC in" -Description "Allow DCs to communicate in" -Direction Inbound -RemoteAddress $dc_ips -Action Allow -Group "DC"
      New-NetFirewallRule -DisplayName "DC to DC out" -Description "Allow DCs to communicate out" -Direction Outbound -RemoteAddress $dc_ips -Action Allow -Group "DC"
    }

    # Allow traffic from the DC to the domain machines and vice versa
    New-NetFirewallRule -DisplayName "Allow into DC TCP" -Description "Allow domain machines into DC tcp" -Direction Inbound -Protocol TCP -LocalPort $dc_ports_tcp -RemoteAddress $domain_ips -Action Allow -Group "DC"
    New-NetFirewallRule -DisplayName "Allow DC out TCP" -Description "Allow DC out to domain machine tcp" -Direction Outbound -Protocol TCP -LocalPort $dc_ports_tcp -RemoteAddress $domain_ips -Action Allow -Group "DC"
    New-NetFirewallRule -DisplayName "Allow into DC UDP" -Description "Allow domain machines into DC udp" -Direction Inbound -Protocol UDP -LocalPort $dc_ports_udp -RemoteAddress $domain_ips -Action Allow -Group "DC"
    New-NetFirewallRule -DisplayName "Allow DC out UDP" -Description "Allow DC out to machine udp" -Direction Outbound -Protocol UDP -LocalPort $dc_ports_udp -RemoteAddress $domain_ips -Action Allow -Group "DC"
} else {
    New-NetFirewallRule -DisplayName "Let DC in TCP" -Description "Allow the Domain Controller into the machine on the DC ports in TCP" -Direction Inbound -Protocol TCP -RemotePort $dc_ports_tcp -RemoteAddress $dc_ips -Action Allow -Group "DC"
    New-NetFirewallRule -DisplayName "Let DC in UDP" -Description "Allow the Domain Controller into the machine on the DC ports in UDP" -Direction Inbound -Protocol UDP -RemotePort $dc_ports_udp -RemoteAddress $dc_ips -Action Allow -Group "DC"
    New-NetFirewallRule -DisplayName "Let out to DC TCP" -Description "Allow the machine to communicate out to the DC in TCP" -Direction Outbound -Protocol TCP -RemotePort $dc_ports_tcp -RemoteAddress $dc_ips -Action Allow -Group "DC"
    New-NetFirewallRule -DisplayName "Let out to DC UDP" -Description "Allow the machine to communicate out to the DC in UDP" -Direction Outbound -Protocol UDP -RemotePort $dc_ports_udp -RemoteAddress $dc_ips -Action Allow -Group "DC"
}

# Disable Internet rules
Disable-NetFirewallRule -Group "Internet"

# Enable firewalls
Set-NetFirewallProfile -All -Enabled True -DefaultOutboundAction Block
