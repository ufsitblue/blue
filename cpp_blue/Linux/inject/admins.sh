#!/bin/sh
# @d_tranman/Nigel Gerald/Nigerald

cat /etc/group | grep -E '(sudo|wheel)' | awk -F ':' '{print $4}'
