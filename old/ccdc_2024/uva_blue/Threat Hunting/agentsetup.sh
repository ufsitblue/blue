#!/bin/bash

RHEL(){
    yum install -y -q rsyslog
    echo "\$ModLoad imdup" >> /etc/rsyslog.conf
    echo "\$UDPServerRun 514" >> /etc/rsyslog.conf
    echo "if \$fromhost-ip starts with '$Range' then /var/log/remote/rsyslog.log" >> /etc/rsyslog.conf
    echo "& ~" 
}

DEBIAN(){
    apt-get install -y -qq rsyslog
    echo "\$ModLoad imdup" >> /etc/rsyslog.conf
    echo "\$UDPServerRun 514" >> /etc/rsyslog.conf
    echo "if \$fromhost-ip starts with '$Range' then /var/log/remote/rsyslog.log" >> /etc/rsyslog.conf
    echo "& ~" 
}


if command -v yum >/dev/null ; then
    RHEL
elif command -v apt-get >/dev/null ; then
    DEBIAN
fi