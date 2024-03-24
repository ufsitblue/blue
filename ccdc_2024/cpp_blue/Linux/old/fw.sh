#!/bin/sh
# Thank you Mr. DSU Fabriel Gawk for the gawk gawk 2000 like script that may or may not work

ipt=$(command -v iptables || command -v /sbin/iptables || command -v /usr/sbin/iptables)

if [ -z "$PORTS" ] || [ -z "$LOCALPORTS" ] || [ -z "$LOCALNETWORK" ] || [ -z "$OUTBOUNDPORTS" ]; then
    echo "One or more variables are empty. Exiting to prevent lockout."
    exit 1
fi

$ipt -P INPUT ACCEPT ; $ipt -P OUTPUT ACCEPT ; $ipt -P FORWARD ACCEPT ; $ipt -F; $ipt -X

$ipt -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
$ipt -A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

$ipt -A INPUT -p tcp -m multiport --dport 22,$PORTS -m conntrack --ctstate NEW -j ACCEPT

$ipt -A INPUT -p tcp -m multiport --dports $LOCALPORTS -s 127.0.0.1,$LOCALNETWORK -m conntrack --ctstate NEW -j ACCEPT

$ipt -A OUTPUT -p tcp -m multiport --dports $OUTBOUNDPORTS -d 127.0.0.1,$LOCALNETWORK -m conntrack --ctstate NEW -j ACCEPT

$ipt -A INPUT -p udp -m multiport --dports 53,514 -s 127.0.0.1,$LOCALNETWORK -j ACCEPT
$ipt -A OUTPUT -p udp -m multiport --dports 53,514 -s 127.0.0.1,$LOCALNETWORK -j ACCEPT

$ipt -P FORWARD ACCEPT; $ipt -P OUTPUT DROP; $ipt -P INPUT DROP

iptables-save > /opt/rules.v4
