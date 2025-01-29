#!/bin/sh
# @d_tranman/Nigel Gerald/Nigerald
ipt=$(command -v iptables || command -v /sbin/iptables || command -v /usr/sbin/iptables)

if [ -z "$ipt" ]; then
    echo "NO IPTABLES ON THIS SYSTEM, GOOD LUCK"
    exit 1
fi

if [ -z "$LOCALNETWORK" ]; then
    echo "LOCALNETWORK not defined."
    exit 1
fi

if [ -z "$CCSHOST" ] && [ -z "$NOTNATS" ]; then
    echo "CCSHOST not defined and WE ARE AT NATS BRO!"
    exit 1
fi

$ipt -P OUTPUT ACCEPT ; $ipt -P FORWARD ACCEPT ; $ipt -F; $ipt -X ;$ipt -P INPUT ACCEPT 

$ipt -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
$ipt -A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

if [ -n "$CCSHOST" ]; then
    $ipt -A OUTPUT -d $CCSHOST -j ACCEPT
    $ipt -A INPUT -s $CCSHOST -j ACCEPT
fi

$ipt -A OUTPUT -d 127.0.0.1,$LOCALNETWORK -m conntrack --ctstate NEW -j ACCEPT

$ipt -A INPUT -p udp -m multiport --dports 53,514 -s 127.0.0.1,$LOCALNETWORK -j ACCEPT
$ipt -A OUTPUT -p udp -m multiport --dports 53,514 -s 127.0.0.1,$LOCALNETWORK -j ACCEPT

$ipt -A INPUT -s 127.0.0.1 -j ACCEPT

$ipt -P FORWARD ACCEPT; $ipt -P OUTPUT DROP;

iptables-save > /opt/rules.v4
