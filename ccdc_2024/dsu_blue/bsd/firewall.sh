#!/bin/bash

# rc.conf
echo "pf_enable=”yes”" >> /etc/rc.conf
echo "pf_rules=”/etc/pf.conf”" >> /etc/rc.conf

# pf.conf
echo "block all" >> /etc/pf.conf
echo "pass in proto tcp to port 22" >> /etc/pf.conf
echo "#pass in proto tcp to port {X, X, X}" >> /etc/pf.conf

# reload firewall service, load kenel mod
kldload pf 2>/dev/null
pfctl -e 2>/dev/null
service pf start 2>/dev/null