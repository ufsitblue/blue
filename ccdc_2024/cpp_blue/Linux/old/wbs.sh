#!/bin/sh

for shell in $(cat /etc/shells | grep "/"); do
    setfacl -m 'www-data:---' $shell 2>/dev/null
    setfacl -m 'tomcat:---' $shell 2>/dev/null
    setfacl -m 'apache:---' $shell 2>/dev/null
done