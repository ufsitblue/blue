#!/bin/sh
# @d_tranman/Nigel Gerald/Nigerald
RHEL(){
  cat /var/log/secure | grep 'Failed password' | wc -l
}

DEBIAN(){
  cat /var/log/auth.log | grep 'Failed password' | wc -l
}

UBUNTU(){
  DEBIAN
}

ALPINE(){
  DEBIAN
}

SLACK(){
  RHEL
}

if command -v yum >/dev/null ; then
    RHEL
elif command -v apt-get >/dev/null ; then
    if $(cat /etc/os-release | grep -qi Ubuntu); then
        UBUNTU
    else
        DEBIAN
    fi
elif command -v apk >/dev/null ; then
    ALPINE
elif command -v slapt-get >/dev/null || (cat /etc/os-release | grep -i slackware) ; then
    SLACK
fi
