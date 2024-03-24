#!/bin/sh
# @d_tranman/Nigel Gerald/Nigerald and c0ve

RHEL(){
    yum check-update -y >/dev/null
    yum install net-tools iproute sed curl wget bash -y > /dev/null
    yum install iptraf -y >/dev/null

    yum install auditd -y > /dev/null
    yum install rsyslog -y > /dev/null
}

DEBIAN(){
    apt-get -qq update >/dev/null
    apt-get -qq install net-tools iproute2 sed curl wget bash -y >/dev/null
    apt-get -qq install iptraf -y >/dev/null

    apt-get -qq install auditd rsyslog -y >/dev/null
}

UBUNTU(){
  DEBIAN
}

ALPINE(){
    echo "http://mirrors.ocf.berkeley.edu/alpine/v3.16/community" >> /etc/apk/repositories
    apk update >/dev/null
    apk add iproute2 net-tools curl wget bash iptraf-ng iptables util-linux-misc >/dev/null

    apk add audit rsyslog >/dev/null

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


# backup /etc/passwd
mkdir /root/.cache
cp /etc/passwd /root/.cache/users

# check our ports
( netstat -tlpn || ss -plnt ) > /root/.cache/listen
( netstat -tpwn || ss -pnt | grep ESTAB ) > /root/.cache/estab

# pam
mkdir /etc/pam.d/pam/
cp -R /etc/pam.d/ /root/.cache/pam

# profiles
for f in '.profile' '.*shrc' '.*sh_login'; do
    find /home /root -name "$f" -exec rm {} \;
done

