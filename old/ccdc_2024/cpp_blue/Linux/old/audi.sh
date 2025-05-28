#!/bin/sh
# c0ve and @d_tranman/Nigel Gerald/Nigerald

url="https://raw.githubusercontent.com/socfortress/Wazuh-Rules/main/Auditd/auditd.conf"
wget $url || ( curl $url >  auditd.conf)
cp auditd.conf /etc/audit/audit.rules
cp auditd.conf /etc/audit/rules.d/audit.rules
echo "-w /etc/rc.local -p wa -k possible_rcscript_attack" >> /etc/audit/rules.d/audit.rules
echo "-w /etc/ld.so.preload -p wa -k possible_preload_hijack" >> /etc/audit/rules.d/audit.rules

RHEL(){
    yum install -y -q audit
    
}

DEBIAN(){
    apt-get install -y -q auditd
}

UBUNTU(){
    DEBIAN
}

ALPINE(){
    apk add audit
}

SLACK(){
    echo "its fucked"
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
