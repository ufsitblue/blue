#!/bin/bash
# Variables
dc_ips=()
team_ips=()
linux_dc_ports_tcp=("53" "88" "135" "389" "445" "464" "636" "3268" "3269" "49152:65535")
dc_ports_udp=(53 88 123 389 464)

read -p "In domain? (y/n): " in_domain

if [ "$in_domain" == "y" ]; then
    while true; do
        read -p "Enter a Domain Controller IP address (or type 'done' to finish): " ip
        if [ "$ip" == "done" ]; then
            break
        else
            dc_ips+=("$ip")
        fi
    done
fi

while true; do
    read -p "Enter a team IP address (or type 'done' to finish): " ip
    if [ "$ip" == "done" ]; then
        break
    else
        team_ips+=("$ip")
    fi
done

# Determine package manager
if command -v apk &> /dev/null; then
    package_manager="apk"
elif command -v yum &> /dev/null; then
    package_manager="yum"
elif command -v dnf &> /dev/null; then
    package_manager="dnf"
elif command -v apt-get &> /dev/null; then
    package_manager="apt"
elif command -v zypper &> /dev/null; then
    package_manager="zypper"
else
    echo "Unsupported package manager"
    exit 1
fi

# Install iptables if not present
if ! command -v iptables &> /dev/null; then
    case $package_manager in
        "apk") apk add iptables ;;
        "yum") yum install -y iptables ;;
        "dnf") dnf install -y iptables ;;
        "apt") apt-get install -y iptables ;;
        "zypper") zypper install -y iptables ;;
    esac
fi

# Create iptables folder
mkdir -p /etc/iptables

# Create restore script
cat << 'EOF' > /etc/iptables/restore-iptables.sh
#!/bin/bash
# Restore iptables rules
iptables-restore < /root/{{ inventory_hostname }}.rules
EOF

chmod 0500 /etc/iptables/restore-iptables.sh

# Check if using rc-service or systemd
if command -v systemctl &> /dev/null; then
  cat << 'EOF' > /etc/systemd/system/iptables-persistent.service
[Unit] 
Description=runs iptables restore on boot
ConditionFileIsExecutable=/etc/iptables/restore-iptables.sh
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash /etc/iptables/restore-iptables.sh
TimeoutSec=10
RemainAfterExit=yes
GuessMainPID=no

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable iptables-persistent.service
else
  cat << 'EOF' > /etc/init.d/iptables-persistent
#!/sbin/openrc-run

depend() {
  need net
}

command="/bin/bash"
command_args="/etc/iptables/restore-iptables.sh"
pidfile="iptables-persistent.pid"
EOF
  chmod 0550 /etc/init.d/iptables-persistent
  rc-update add iptables-persistent default
fi


# Ensure rsyslog is installed
case $package_manager in
    "apk") apk add rsyslog ;;
    "yum") yum install -y rsyslog ;;
    "dnf") dnf install -y rsyslog ;;
    "apt") apt-get install -y rsyslog ;;
    "zypper") zypper install -y rsyslog ;;
esac

# Flush current rules
iptables -F INPUT
iptables -F OUTPUT

# Add iptables rules
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
iptables -A OUTPUT -m conntrack --ctstate INVALID -j DROP
iptables -A INPUT -s 127.0.0.0/8 -j ACCEPT
iptables -A OUTPUT -d 127.0.0.0/8 -j ACCEPT
iptables -A INPUT -p icmp -j ACCEPT
iptables -A OUTPUT -p icmp -j ACCEPT

# Add team IPs to INPUT chain
for ip in "${team_ips[@]}"; do
    iptables -A INPUT -p tcp --dport 22 -s "$ip" -j ACCEPT
    # Allow established SSH connections
    iptables -A OUTPUT -p tcp --sport 22 -d "$ip" -m conntrack --ctstate ESTABLISHED -j ACCEPT
done


# Add DC rules if in domain
if [ "$in_domain" == "y" ]; then
  for ip in "${dc_ips[@]}"; do
    # DC rules for TCP
    for port in "${linux_dc_ports_tcp[@]}"; do
        iptables -A INPUT -p tcp --sport "$port" -s "$ip" -j ACCEPT
        iptables -A OUTPUT -p tcp --dport "$port" -d "$ip" -j ACCEPT
    done

    # DC rules for UDP
    for port in "${dc_ports_udp[@]}"; do
        iptables -A INPUT -p udp --sport "$port" -s "$ip" -j ACCEPT
        iptables -A OUTPUT -p udp --dport "$port" -d "$ip" -j ACCEPT
    done
  done
fi

echo Adding Drop Rules

# Add dropped input and output LOG rules
iptables -A INPUT -j LOG --log-prefix "[DROPPED_INPUT] "
iptables -A OUTPUT -j LOG --log-prefix "[DROPPED_OUTPUT] "

sleep(30)

# Add cron job to flush rules every 5 minutes
echo "*/5 * * * * root iptables -F" > /etc/cron.d/flush_firewall

echo Removed cron

# Add default DROP rule
iptables -A INPUT -j DROP
iptables -A OUTPUT -j DROP

# Save custom rules
iptables-save > /root/{{ inventory_hostname }}.rules

# Remove crontab entry
sed -i '/iptables -F/d' /etc/cron.d/flush_firewall

# Create rsyslog.d directory
mkdir -p /etc/rsyslog.d

# Add rsyslog file
cat << 'EOF' > /etc/rsyslog.d/00-iptables.conf
:msg, contains, "[DROPPED_INPUT] " /var/log/input.log
:msg, contains, "[DROPPED_OUTPUT] " /var/log/output.log
& stop
EOF

# Restart rsyslog
case $package_manager in
    "apk") rc-service rsyslog restart ;;
    "yum"|"dnf") systemctl restart rsyslog ;;
    "apt") systemctl restart rsyslog ;;
    "zypper") systemctl restart rsyslog ;;
esac
