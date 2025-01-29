#!/bin/sh

( netstat -tlpn || ss -plnt ) > /tmp/listen
( netstat -tpwn || ss -pnt | grep ESTAB ) > /tmp/estab

diff /root/.cache/listen /tmp/listen
diff /root/.cache/estab /tmp/estab

rm /tmp/listen
rm /tmp/estab
