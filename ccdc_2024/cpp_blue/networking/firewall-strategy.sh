iptables -A INPUT -p tcp --sport 22 --source 192.168.1.0/24 -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -m string --algo bm --string "Mozilla/5.0" -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -m length --length 1000: -j ACCEPT
iptables -A INPUT -p icmp -j DROP
iptables -A INPUT -p tcp --dport 8080 -m time --timestart 09:00 --timestop 17:00 --days Fri -j ACCEPT
iptables -A INPUT -p tcp --dport 9999 -j LOG --log-prefix "Blocked Port 9999: " --log-level 7
iptables -A INPUT -p tcp --dport 9999 -j DROP
iptables -A INPUT -p udp --dport 123 -m mac --mac-source 00:11:22:33:44:55 -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --set --name SSH --rsource
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount 2 --name SSH --rsource -j DROP
iptables -A INPUT -p tcp --dport 8080 ! --source 10.0.0.0/24 -j ACCEPT
iptables -A INPUT -p tcp -m geoip --source-country US --dport 111 -j ACCEPT
iptables -A INPUT -p tcp -m geoip --source-country US --dport 2049 -j ACCEPT
iptables -A INPUT -p tcp --dport 5555 -m state --state ESTABLISHED -j ACCEPT
iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
iptables -A INPUT -p tcp --dport 9090 -m string --algo kmp --string "example.com" -j ACCEPT
iptables -A INPUT -p tcp --dport 8080 -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A INPUT -f -j DROP
iptables -A INPUT -p tcp --dport 80 -m iprange --src-range 192.168.1.100-192.168.1.200 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 ! --source 192.168.2.0/24 -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -m state --state NEW -m recent --set --name HTTP --rsource
iptables -A INPUT -p tcp --dport 80 -m state --state NEW -m recent --update --seconds 60 --hitcount 10 --name HTTP --rsource -j DROP
iptables -A INPUT -p tcp --dport 8080 -m state --state ESTABLISHED -m ttl --ttl-gt 100 -j ACCEPT
iptables -A INPUT -p udp --dport 123 -m state --state ESTABLISHED -m u32 --u32 "0>>22&0x3C@12=17" -j ACCEPT