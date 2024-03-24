#!/bin/bash

#NEED TO TEST

function finish {
echo "Setup complete! Browse to ${NEW_IP}:443"
shred -u “$0”
}

# VARIABLES
TEAM_NUMBER="10"  # Change this to your desired team number
# Passwords charset is a-zA-Z0-9.*-?
echo 'Password charset is a-zA-Z0-9.*-?'
read -p 'Enter new Web UI password: ' NEW_PASSWORD
read -p 'Enter new API password: ' API_PASSWORD
DNS="10.${TEAM_NUMBER}0.${TEAM_NUMBER}0.10"

# NETWORKING
NEW_IP="172.16.${TEAM_NUMBER}.155"
DEFAULT_GATEWAY="172.16.${TEAM_NUMBER}.1"

sudo printf "%s\n" "DEVICE=eth0" "ONBOOT=yes" "BOOTPROTO=none" "PREFIX=24" "IPADDR=${NEW_IP}" "GATEWAY=${DEFAULT_GATEWAY}" "DNS1=${DNS}" "DEFROUTE=yes" "IPV4_FAILURE_FATAL=no" "NAME=eth0" > /etc/sysconfig/network-scripts/ifcfg-eth0

echo "Networking Complete"

# PASSWORDS
# Make Password File
sudo printf "%s\n" "#Web UI Login" " indexer_username: admin" " indexer_password: ${NEW_PASSWORD}" "" "#API Login" " api_username: wazuh" " api_password: ${API_PASSWORD}" > file.yml

# Change Passwords
# Use default api user and password
sudo bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/wazuh-passwords-tool.sh -a -f file.yml -au wazuh -ap wazuh

#Delete Password File
sudo shred -u file.yml

echo "Passwords Complete"

# FIREWALL
sudo iptables -A INPUT -p tcp -s ${DEFAULT_GATEWAY}/24 --dport 443 -j ACCEPT
sudo iptables -A INPUT -p tcp -s ${DEFAULT_GATEWAY}/24 --dport 1514 -j ACCEPT
sudo iptables -A INPUT -p tcp -s ${DEFAULT_GATEWAY}/24 --dport 1515 -j ACCEPT

# Allow DNS Out (unsure if necessary)
#sudo iptables -A OUTPUT -p udp --dport 53 -d ${DNS} -j ACCEPT
#sudo iptables -A OUTPUT -p tcp --dport 53 -d ${DNS} -j ACCEPT

# Firewall Defaults
sudo iptables -A INPUT -j DROP
sudo iptables -P OUTPUT DROP
sudo iptables -P FORWARD DROP

# Save Firewall Rules
sudo iptables-save > /etc/network/iptables.rules

echo "Firewalls Complete"

# Check status of indexer
sudo systemctl status wazuh-indexer || { sudo mkdir /etc/system/system/wazuh-indexer.service.d; sudo printf "%s\n" "[Service]" "TimeoutStartSec=180" > /etc/system/system/wazuh-indexer.service.d/startup-timeout.conf [Service]; }

# Reload Daemon
sudo systemctl daemon-reload

# START WAZUH
sudo systemctl restart wazuh-indexer
sudo systemctl restart wazuh-manager
sudo systemctl restart wazuh-dashboard

trap finish EXIT