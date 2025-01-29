#!/bin/sh

ALPINE(){
  apk add rsyslog
  echo "*.*@$AgentIP:514" >> /etc/rsyslog.conf
  service rsyslog restart
}

SLACK(){
  echo "*.*@$AgentIP:514" >> /etc/syslog.conf
}


if command -v apk >/dev/null ; then
    ALPINE
elif command -v slapt-get >/dev/null || (cat /etc/os-release | grep -i slackware) ; then
    SLACK
fi
