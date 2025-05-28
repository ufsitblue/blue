#!/bin/bash
iptables -I INPUT 2 -p udp --sport 53 -j ACCEPT
iptables -I OUTPUT 2 -p udp --dport 53 -j ACCEPT
iptables -I OUTPUT 2 -p tcp --dport 80 -j ACCEPT
iptables -I OUTPUT 2 -p tcp --dport 443 -j ACCEPT
iptables -I OUTPUT 2 -p udp --dport 443 -j ACCEPT
iptables -I INPUT 2 -p tcp --sport 80 -m state --state ESTABLISHED -j ACCEPT
iptables -I INPUT 2 -p tcp --sport 443 -m state --state ESTABLISHED -j ACCEPT
iptables -I INPUT 2 -p udp --sport 443 -m state --state ESTABLISHED -j ACCEPT
