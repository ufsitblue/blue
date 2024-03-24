#!/bin/sh
# @c0ve. and 1% @hgwj
if [ -z "$IP" ]; then
    echo "missing IP"
    exit 1
fi


RHEL(){
    yum check-update -y >/dev/null
    
    yum install auditd -y > /dev/null
    yum install rsyslog -y > /dev/null
    yum install curl -y > /dev/null
    
    chcon -R -t var_log_t /var/log/audit
}

DEBIAN(){
    apt-get -qq update >/dev/null
    apt-get -qq install auditd rsyslog curl -y >/dev/null
}

UBUNTU(){
    if $(cat /etc/os-release | grep -qi 'Ubuntu 16'); then
        UBU16=true
    fi
    DEBIAN
}

ALPINE(){
    ALP=true
    echo "http://mirrors.ocf.berkeley.edu/alpine/v3.16/community" >> /etc/apk/repositories
    apk update --allow-untrusted >/dev/null
    apk add audit rsyslog curl --allow-untrusted >/dev/null
    mkdir /etc/rsyslog.d
    mkdir /var/log/audit
    grep -rl "dispatcher" /etc/audit/auditd.conf | xargs sed -ri "s/^(dispatcher.*)/dispatcher = \/usr\/sbin\/audispd/g"
}

SLACK(){
    echo "Its Slackware"
}

DRAGONFLY(){
    DF=true
    echo "DragonFly linux. No idea where auditd is lmao"
    cp /usr/local/etc/pkg/repos/df-latest.conf.sample /usr/local/etc/pkg/repos/df-latest.conf
    pkg update >/dev/null
    pkg install -y rsyslog >/dev/null 
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
elif command -v pkg >/dev/null && (cat /etc/os-release | grep -i dragonfly); then
    DRAGONFLY
fi

if [ ! $DF ]; then
    auditctl -b 8192
    auditctl -a exit,always -F arch=b64 -S 59 -k exec_rule
    auditctl -a exit,always -F arch=b32 -S 11 -k exec_rule
    auditctl -a exit,always -F arch=b64 -S 43 -k accept_rule
    auditctl -a never,user -F subj_type=crond_t
    auditctl -a never,exit -F subj_type=crond_t
    if [ ! $UBU16 ]; then
        grep -rl "log_format" /etc/audit | xargs sed -ri "s/^(log_format.*)/log_format = ENRICHED/g"
    fi
fi

if [ ! -d '/etc/rsyslog.d' ]; then
    mkdir /etc/rsyslog.d
fi

if [ $ALP ]; then 
    cat << EOF >> /etc/rsyslog.d/69-remote.conf
    # Alpine Auth
    \$InputFileName /var/log/messages
    \$InputFileStateFile auth_log
    \$InputFileTag auth_log
    \$InputFileSeverity info
    \$InputFileFacility local1
    \$InputRunFileMonitor
    EOF
fi


cat << EOF >> /etc/rsyslog.d/69-remote.conf

# Ubuntu Auth 
\$ModLoad imfile 
\$InputFileName /var/log/auth.log 
\$InputFileStateFile auth_log 
\$InputFileTag auth_log 
\$InputFileSeverity info
\$InputFileFacility local1
\$InputRunFileMonitor

# CentOS Auth
\$InputFileName /var/log/secure
\$InputFileStateFile auth_log
\$InputFileTag auth_log
\$InputFileSeverity info
\$InputFileFacility local1
\$InputRunFileMonitor

# Ubuntu Apache2
\$InputFileName /var/log/apache2/access.log
\$InputFileStateFile access_log
\$InputFileTag access_log
\$InputFileSeverity info
\$InputFileFacility local2
\$InputRunFileMonitor

# RHEL Apache2
\$InputFileName /var/log/httpd/access_log
\$InputFileStateFile access_log
\$InputFileTag access_log
\$InputFileSeverity info
\$InputFileFacility local2
\$InputRunFileMonitor

# Nginx
\$InputFileName /var/log/nginx/access.log
\$InputFileStateFile access_log
\$InputFileTag access_log
\$InputFileSeverity info
\$InputFileFacility local2
\$InputRunFileMonitor

# Honeypot logging (thepot.sh)
\$InputFileName /var/log/honeypot
\$InputFileStateFile honeypot
\$InputFileTag honeypot
\$InputFileSeverity info
\$InputFileFacility local3
\$InputRunFileMonitor

# MySQL logging
\$InputFileName /var/log/mysql/mysql.log
\$InputFileStateFile database
\$InputFileTag database
\$InputFileSeverity info
\$InputFileFacility local4
\$InputRunFileMonitor

# MariaDB Logging
\$InputFileName /var/log/mariadb/mariadb_query.log
\$InputFileStateFile database
\$InputFileTag database
\$InputFileSeverity info
\$InputFileFacility local4
\$InputRunFileMonitor

# AuditDeez
\$InputFileName /var/log/audit/audit.log
\$InputFileStateFile audit
\$InputFileTag audit
\$InputFileSeverity info
\$InputFileFacility local5
\$InputRunFileMonitor

*.* @$IP:514    
&stop
EOF
if [ ! $ALP ]; then
    if command -v systemctl >/dev/null; then
        systemctl restart rsyslog
        systemctl start auditd
    else 
        service rsyslog restart
        service auditd start
    fi
else
    service rsyslog restart
    /usr/sbin/auditd &
fi