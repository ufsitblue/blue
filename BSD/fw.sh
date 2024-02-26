#!/bin/bash

# Flush current rules
ipfw -q flush

# icmp/loopback rules
ipfw add allow icmp from any to any
ipfw add allow from any to any on lo0

# input rules
ipfw add allow from 10.0.0.4 to any port 22,80,443 in

# output rules
ipfw add allow from any port 22,80,443 to 10.0.0.4 out keep-state

#drop rule
ipfw add drop from any to any
