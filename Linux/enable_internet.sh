iptables -I INPUT 1 -p udp --sport 53 -j ACCEPT
iptables -I OUTPUT 1 -p udp --dport 53 -j ACCEPT
iptables -I OUTPUT 1 -p tcp --dport 80 -j ACCEPT
iptables -I OUTPUT 1 -p tcp --dport 443 -j ACCEPT
iptables -I OUTPUT 1 -p udp --dport 443 -j ACCEPT
iptables -I INPUT 1 -p tcp --sport 80 -m state --state ESTABLISHED -j ACCEPT
iptables -I INPUT 1 -p tcp --sport 443 -m state --state ESTABLISHED -j ACCEPT
iptables -I INPUT 1 -p udp --sport 443 -m state --state ESTABLISHED -j ACCEPT
