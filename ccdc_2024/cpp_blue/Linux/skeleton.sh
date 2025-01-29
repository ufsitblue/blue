#!/bin/sh
# @d_tranman/Nigel Gerald/Nigerald

if [ -z "$SOMEVAR" ]; then
    echo "SOMEVAR Not defined. Exiting cuz yeah. Or just delete this block lol."
    exit 1
fi

RHEL(){
  echo rhel
}

DEBIAN(){
  echo debian
}

UBUNTU(){
  echo ubuntu
}

ALPINE(){
  echo alpoop
}

SLACK(){
  echo slack
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
