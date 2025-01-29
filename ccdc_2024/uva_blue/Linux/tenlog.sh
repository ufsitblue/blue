#!/bin/sh

RHEL(){
  cat /var/log/secure | grep -E '(Failed|Accepted) password'  | awk -F 'for' '{print $2}' | awk  '{ if ($1 != "invalid" && $2 != "user") { print $1 } else { print $3 } }' | sort | uniq -c | sort -nr
}

DEBIAN(){
  cat /var/log/auth.log | grep -E '(Failed|Accepted) password'  | awk -F 'for' '{print $2}' | awk  '{ if ($1 != "invalid" && $2 != "user") { print $1 } else { print $3 } }' | sort | uniq -c | sort -nr
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
