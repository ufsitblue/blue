# firewall
mv `which iptables` /sbin/yfa 2>/dev/null

cat << 'EOF' > /root/fw.sh
set -e
ipt="/sbin/yfa iptables"
$ipt -F; $ipt -X
$ipt -A INPUT -p tcp -m multiport --dport 22,[p] -j ACCEPT

# Allow existing connections
$ipt -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
$ipt -A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# Allow web out
$ipt -A OUTPUT -p tcp -m multiport --dport 80,443 -j ACCEPT

# DNS
$ipt -A INPUT -p udp --dport 53 -j ACCEPT
$ipt -A OUTPUT -p udp --dport 53 -j ACCEPT

# For ICMP
# $ipt -A INPUT -p icmp -s IP.RANGE -j ACCEPT

# Multiport example (ftp)
# $ipt -A INPUT -p tcp -m multiport --dports 65500:65535 -j ACCEPT

# Default policies
$ipt -P FORWARD DROP; $ipt -P OUTPUT DROP; $ipt -P INPUT DROP
EOF

echo "[+] Dropped firewall script at /root/fw.sh. Configure and run it to your liking."

# make persistent
# bash ./fw.sh; sleep 10; yfa iptables -P INPUT ACCEPT; yfa iptables -P OUTPUT ACCEPT
