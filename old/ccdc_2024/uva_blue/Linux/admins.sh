#!/bin/sh
cat /etc/group | grep -E '(sudo|wheel)' | awk -F ':' '{print $4}'
