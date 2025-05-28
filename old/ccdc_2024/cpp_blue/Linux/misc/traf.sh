#!/bin/sh
# @d_tranman/Nigel Gerald/Nigerald

cat /var/log/iptra*/*.log | awk -F ';' '{print $5}' | awk '{print $2}' | sort | uniq -c | sort -rn | head -n 10
