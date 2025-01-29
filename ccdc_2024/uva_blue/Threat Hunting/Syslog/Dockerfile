FROM ubuntu

RUN apt update && apt install rsyslog -y
RUN echo '$ModLoad imudp\n\
$UDPServerRun 514 \n\
$template Auth_Log, "/var/log/remote/auth_log \n\
$template Access_Log, "/var/log/remote/access_log" \n\
$template Event_Log, "/var/log/remote/event_log" \n\
$template Honeypot, "/var/log/remote/honeypot" \n\
$template Database, "/var/log/remote/database" \n\
$template Audit, "/var/log/remote/audit" \n\
local1.* ?Auth_Log \n\
local2.* ?Access_Log \n\
local3.* ?Honeypot \n\
local4.* ?Database \n\
local5.* ?Audit ' > /etc/rsyslog.conf

ENTRYPOINT [ "rsyslogd", "-n" ]