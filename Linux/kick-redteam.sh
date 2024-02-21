#!/bin/bash

# Only works on Debian/Ubuntu, you need the iptables-persistent package for this to work
# Needs to be run as root.

wall nice try buddy
if [ $# -eq 0 ]; then
	echo "Not blocking IP addresses - no IP supplied"
else
	iptables -I INPUT -s $1 -j DROP
	iptables -I OUTPUT -d $1 -j DROP
fi
iptables-save > /etc/iptables/rules.v4
ip6tables-save > /etc/iptables/rules.v6
sleep 2
reboot
