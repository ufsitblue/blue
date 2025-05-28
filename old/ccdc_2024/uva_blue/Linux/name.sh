#!/bin/sh
hostname
 ( ip a | grep -oE '([[:digit:]]{1,3}\.){3}[[:digit:]]{1,3}/[[:digit:]]{1,2}' | grep -v '127.0.0.1' ) || ( ifconfig | grep -E 'inet\s([[:digit:]]{1,3}\.){3}[[:digit:]]{1,3}' | grep -v '127.0.0.1' )
