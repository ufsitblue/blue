#!/bin/sh
# @d_tranman/Nigel Gerald/Nigerald

IS_RHEL=false
IS_DEBIAN=false
IS_ALPINE=false
IS_SLACK=false

ORAG=''
GREEN=''
YELLOW=''
BLUE=''
RED=''
NC=''

if [ -z "$DEBUG" ]; then
    DPRINT() { 
        "$@" 2>/dev/null 
    }
else
    DPRINT() { 
        "$@" 
    }
fi

RHEL(){
  IS_RHEL=true
}

DEBIAN(){
  IS_DEBIAN=true
}

UBUNTU(){
  DEBIAN
}

ALPINE(){
  IS_ALPINE=true
}

SLACK(){
  IS_SLACK=true
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
elif command -v slapt-get >/dev/null || (cat /etc/os-release | grep -qi slackware ) ; then
    SLACK
fi

if [ -n "$COLOR" ]; then
    ORAG='\033[0;33m'
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;36m'
    NC='\033[0m'
fi

echo -e "${GREEN}
##################################
#                                #
#         INVENTORY TIME         #
#                                #
##################################
${NC}\n"

echo -e "\n${GREEN}#############HOST INFORMATION############${NC}\n"

HOST=$( DPRINT hostname || DPRINT cat /etc/hostname )
OS=$( cat /etc/*-release  | grep PRETTY_NAME | sed 's/PRETTY_NAME=//' | sed 's/"//g' )
if command -v 'ip' > /dev/null ; then
    IP=$( DPRINT ip a | grep -oE '([[:digit:]]{1,3}\.){3}[[:digit:]]{1,3}/[[:digit:]]{1,2}' | grep -v '127.0.0.1' )
elif command -v 'ifconfig' > /dev/null ; then 
    IP=$( DPRINT ifconfig | grep -oE 'inet.+([[:digit:]]{1,3}\.){3}[[:digit:]]{1,3}' | grep -v '127.0.0.1' ) 
else
    IP="ip a and ifconifg command not found"
fi
USERS=$( cat /etc/passwd | grep -vE '(false|nologin|sync)$' | grep -E '/.*sh$' )
SUDOERS=$( DPRINT cat /etc/sudoers /etc/sudoers.d/*  | grep -vE '#|Defaults|^\s*$' | grep -vE '(Cmnd_Alias|\\)' )
SUIDS=$(find /bin /sbin /usr -perm -u=g+s -type f -exec ls -la {} \; | grep -E '(s7z|aa-exec|ab|agetty|alpine|ansible-playbook|ansible-test|aoss|apt|apt-get|ar|aria2c|arj|arp|as|ascii85|ascii-xfr|ash|aspell|at|atobm|awk|aws|base32|base58|base64|basenc|basez|bash|batcat|bc|bconsole|bpftrace|bridge|bundle|bundler|busctl|busybox|byebug|bzip2|c89|c99|cabal|cancel|capsh|cat|cdist|certbot|check_by_ssh|check_cups|check_log|check_memory|check_raid|check_ssl_cert|check_statusfile|chmod|choom|chown|chroot|clamscan|cmp|cobc|column|comm|composer|cowsay|cowthink|cp|cpan|cpio|cpulimit|crash|crontab|csh|csplit|csvtool|cupsfilter|curl|cut|dash|date|dd|debugfs|dialog|diff|dig|distcc|dmesg|dmidecode|dmsetup|dnf|docker|dos2unix|dosbox|dotnet|dpkg|dstat|dvips|easy_install|eb|ed|efax|elvish|emacs|enscript|env|eqn|espeak|ex|exiftool|expand|expect|facter|file|find|finger|fish|flock|fmt|fold|fping|ftp|gawk|gcc|gcloud|gcore|gdb|gem|genie|genisoimage|ghc|ghci|gimp|ginsh|git|grc|grep|gtester|gzip|hd|head|hexdump|highlight|hping3|iconv|iftop|install|ionice|ip|irb|ispell|jjs|joe|join|journalctl|jq|jrunscript|jtag|julia|knife|ksh|ksshell|ksu|kubectl|latex|latexmk|ldconfig|ld.so|less|lftp|ln|loginctl|logsave|look|lp|ltrace|lua|lualatex|luatex|lwp-download|lwp-request|mail|make|man|mawk|minicom|more|mosquitto|msfconsole|msgattrib|msgcat|msgconv|msgfilter|msgmerge|msguniq|mtr|multitime|mv|mysql|nano|nasm|nawk|nc|ncftp|neofetch|nft|nice|nl|nm|nmap|node|nohup|npm|nroff|nsenter|octave|od|openssl|openvpn|openvt|opkg|pandoc|paste|pax|pdb|pdflatex|pdftex|perf|perl|perlbug|pexec|pg|php|pic|pico|pidstat|pip|pkexec|pkg|posh|pr|pry|psftp|psql|ptx|puppet|pwsh|python|rake|rc|readelf|red|redcarpet|redis|restic|rev|rlogin|rlwrap|rpm|rpmdb|rpmquery|rpmverify|rsync|rtorrent|ruby|run-mailcap|run-parts|runscript|rview|rvim|sash|scanmem|scp|screen|script|scrot|sed|service|setarch|setfacl|setlock|sftp|sg|shuf|slsh|smbclient|snap|socat|socket|soelim|softlimit|sort|split|sqlite3|sqlmap|ss|ssh|ssh-agent|ssh-keygen|ssh-keyscan|sshpass|start-stop-daemon|stdbuf|strace|strings|sysctl|systemctl|systemd-resolve|tac|tail|tar|task|taskset|tasksh|tbl|tclsh|tcpdump|tdbtool|tee|telnet|terraform|tex|tftp|tic|time|timedatectl|timeout|tmate|tmux|top|torify|torsocks|troff|tshark|ul|unexpand|uniq|unshare|unsquashfs|unzip|update-alternatives|uudecode|uuencode|vagrant|valgrind|vi|view|vigr|vim|vimdiff|vipw|virsh|volatility|w3m|wall|watch|wc|wget|whiptail|whois|wireshark|wish|xargs|xdg-user-dir|xdotool|xelatex|xetex|xmodmap|xmore|xpad|xxd|xz|yarn|yash|yelp|yum|zathura|zip|zsh|zsoelim|zypper)$')
WORLDWRITEABLES=$( DPRINT find /usr /bin/ /sbin /var/www /lib -perm -o=w -type f -exec ls {} -la \; )
if [ $IS_RHEL = true ] || [ $IS_ALPINE = true ]; then
    SUDOGROUP=$( cat /etc/group | grep wheel | sed 's/x:.*:/\ /' )
else
    SUDOGROUP=$( cat /etc/group | grep sudo | sed 's/x:.*:/\ /' )
fi

echo -e "${BLUE}[+] Hostname:${NC} $HOST"
echo -e "${BLUE}[+] OS:${NC} $OS"
echo -e "${BLUE}[+] IP Addresses and interfaces${NC}"
echo -e "$IP\n"
echo -e "${BLUE}[+] Users${NC}"
echo -e "${YELLOW}$USERS${NC}\n"
echo -e "${BLUE}[+] /etc/sudoers and /etc/sudoers.d/*${NC}"
echo -e "${YELLOW}$SUDOERS${NC}\n"
echo -e "${BLUE}[+] Sudo group${NC}"
echo -e "${YELLOW}$SUDOGROUP${NC}\n"
echo -e "${BLUE}[+] Funny SUIDs${NC}"
echo -e "${YELLOW}$SUIDS${NC}\n"
echo -e "${BLUE}[+] World Writeable Files${NC}"
echo -e "${YELLOW}$WORLDWRITEABLES${NC}\n"
echo -e "${GREEN}#############Listening Ports############${NC}"
echo ""
if command -v netstat >/dev/null; then
    DPRINT netstat -tlpn | tail -n +3 | awk '{print $1 " " $4 " " $6 " " $7}'| DPRINT column -t
elif command -v ss > /dev/null; then
    DPRINT ss -blunt -p | tail -n +2 | awk '{print $1 " " $5 " " $7}' | DPRINT column -t 
else
    echo "Netstat and ss commands do not exist"
fi
echo ""
echo -e "${GREEN}#############SERVICE INFORMATION############${NC}"
if [ $IS_ALPINE = true ]; then
    SERVICES=$( rc-status -s | grep started | awk '{print $1}' )
elif [ $IS_SLACK = true ]; then
    SERVICES=$( ls -la /etc/rc.d | grep rwx | awk '{print $9}' ) 
else
    SERVICES=$( DPRINT systemctl --type=service | grep active | awk '{print $1}' || service --status-all | grep -E '(+|is running)' )
fi
APACHE2=false
NGINX=false
checkService()
{
    serviceList=$1
    serviceToCheckExists=$2
    serviceAlias=$3                

    if [ -n "$serviceAlias" ]; then
        echo -e "\n${BLUE}[+] $serviceToCheckExists is on this machine${NC}\n"
        if echo "$serviceList" | grep -qi "$serviceAlias\|$serviceToCheckExists" ; then
            if [ "$( DPRINT netstat -tulpn | grep -i $serviceAlias )" ] ; then
                
                echo -e "Active on port(s) ${YELLOW}$(netstat -tulpn | grep -i "$serviceAlias\|$serviceToCheckExists"| awk 'BEGIN {ORS=" and "} {print $1, $4}' | sed 's/\(.*\)and /\1\n/')${NC}\n"
            
            elif [ "$( DPRINT ss -blunt -p | grep -i $serviceAlias )" ] ; then
                
                echo -e "Active on port(s) ${YELLOW}$(ss -blunt -p | grep -i "$serviceAlias\|$serviceToCheckExists"| awk 'BEGIN {ORS=" and " } {print $1,$5}' | sed 's/\(.*\)and /\1\n/')${NC}\n"
            fi

        fi 
    elif echo "$serviceList" | grep -qi "$serviceToCheckExists" ; then
        echo -e "\n${BLUE}[+] $serviceToCheckExists is on this machine${NC}\n"

        if [ "$( DPRINT netstat -tulpn | grep -i $serviceToCheckExists )" ] ; then
                
                echo -e "Active on port(s) ${YELLOW}$(netstat -tulpn | grep -i $serviceToCheckExists| awk 'BEGIN {ORS=" and "} {print $1, $4}' | sed 's/\(.*\)and /\1\n/')${NC}\n"
        
        elif [ "$( DPRINT ss -blunt -p | grep -i $serviceToCheckExists )" ] ; then
                
                echo -e "Active on port(s) ${YELLOW}$(ss -blunt -p | grep -i $serviceToCheckExists| awk 'BEGIN {ORS=" and " } {print $1,$5}' | sed 's/\(.*\)and /\1\n/')${NC}\n"
        fi
    fi
}

if checkService "$SERVICES"  'ssh' | grep -qi "is on this machine"; then checkService "$SERVICES"  'ssh' ; SSH=true ;fi
if checkService "$SERVICES"  'docker' | grep -qi "is on this machine"; then
    checkService "$SERVICES"  'docker'

    ACTIVECONTAINERS=$( docker ps )
    if [ -n "$ACTIVECONTAINERS" ]; then
        echo "Current Active Containers"
        echo -e "${ORAG}$ACTIVECONTAINERS${NC}\n"
    fi

    ANONMOUNTS=$( docker ps -q | DPRINT xargs -n 1 docker inspect --format '{{if .Mounts}}{{.Name}}: {{range .Mounts}}{{.Source}} -> {{.Destination}}{{end}}{{end}}' | grep -vE '^$' | sed 's/^\///g' )
    if [ -n "$ANONMOUNTS" ]; then
        echo "Anonymous Container Mounts (host -> container)"
        echo -e "${ORAG}$ANONMOUNTS${NC}\n"
    fi

    VOLUMES="$( DPRINT docker volume ls --format "{{.Name}}" )"
    if [ -n "$VOLUMES" ]; then
        echo "Volumes"
        for v in $VOLUMES; do
            container=$( DPRINT docker ps -a --filter volume=$v --format '{{.Names}}' | tr '\n' ',' | sed 's/,$//g' )
            if [ -n "$container" ]; then
                mountpoint=$( echo $( DPRINT docker volume inspect --format '{{.Name}}: {{.Mountpoint}}' $v ) | awk -F ': ' '{print $2}' )
                echo -e "${ORAG}$v -> $mountpoint used by $container${NC}"
            fi
        done
        echo ""
    fi
fi

if checkService "$SERVICES"  'cockpit' | grep -qi "is on this machine"; then
    checkService "$SERVICES"  'cockpit'
    echo -e "${ORAG}[!] WE PROBABLY SHOULD KILL COCKPIT${NC}"
fi

if checkService "$SERVICES"  'apache2' | grep -qi "is on this machine"; then
    checkService "$SERVICES"  'apache2'
    APACHE2VHOSTS=$(tail -n +1 /etc/apache2/sites-enabled/* | grep -v '#' |grep -E '==>|VirtualHost|^[^[\t]ServerName|DocumentRoot|^[^[\t]ServerAlias|^[^[\t]*Proxy*')
    echo -e "\n[!] Configuration Details\n"
    echo -e "${ORAG}$APACHE2VHOSTS${NC}"
    APACHE2=true
fi

if checkService "$SERVICES"  'ftp' | grep -qi "is on this machine"; then
    checkService "$SERVICES"  'ftp'
    FTPCONF=$(cat /etc/*ftp* | grep -v '#' | grep -E 'anonymous_enable|guest_enable|no_anon_password|write_enable')
    echo -e "\n[!] Configuration Details\n"
    echo -e "${ORAG}$FTPCONF${NC}"
fi


if checkService "$SERVICES"  'nginx' | grep -qi "is on this machine"; then
    checkService "$SERVICES"  'nginx'
    NGINXCONFIG=$(tail -n +1 /etc/nginx/sites-enabled/* | grep -v '#'  | grep -E '==>|server|^[^[\t]listen|^[^[\t]root|^[^[\t]server_name|proxy_*')
    echo -e "\n[!] Configuration Details\n"
    echo -e "${ORAG}$NGINXCONFIG${NC}"
    NGINX=true
fi

sql_test(){

    if [ -f /lib/systemd/system/mysql.service ]; then
        SQL_SYSD=/lib/systemd/system/mysql.service
    elif [ -f /lib/systemd/system/mariadb.service ]; then
        SQL_SYSD=/lib/systemd/system/mariadb.service
    fi
    
    if [ -n "$SQL_SYSD" ]; then
        SQL_SYSD_INFO=$( grep -RE '^(User=|Group=)' $SQL_SYSD )
    fi
    
    if [ -d /etc/mysql ]; then
        SQLDIR=/etc/mysql
    elif [ -d /etc/my.cnf.d/ ]; then
        SQLDIR=/etc/my.cnf.d/
    fi

    if [ -n "$SQLDIR" ]; then
        SQLCONFINFO=$( DPRINT find $SQLDR *sql*.cnf *-server.cnf | sed 's/:user\s*/ ===> user /' | sed 's/bind-address\s*/ ===> bind-address /' )
    fi

    if [ -n "$SQLCONFINFO" ]; then
        echo -e "${ORAG}$SQLCONFINFO${NC}"
    fi

    if [ -n "$SQL_SYSD_INFO" ]; then
        echo -e "${ORAG}$SQL_SYSD:\n$SQL_SYSD_INFO${NC}\n"
    fi

    SQL_AUTH=1

    if mysql -uroot -e 'bruh' 2>&1 >/dev/null | grep -v '\[Warning\]' | grep -q 'bruh'; then
        echo -e "${RED}Can login as root, with root and no password${NC}\n"
        SQLCMD="mysql -uroot"
    fi

    if mysql -uroot -proot -e 'bruh' 2>&1 >/dev/null | grep -v '\[Warning\]' | grep -q 'bruh'; then
        echo -e "${RED}Can login with root:root${NC}\n"
        SQLCMD="mysql -uroot -proot"
    fi

    if mysql -uroot -ppassword -e 'bruh' 2>&1 >/dev/null | grep -v '\[Warning\]' | grep -q 'bruh'; then
        echo -e "${RED}Can login with root:password${NC}\n"
        SQLCMD="mysql -uroot -ppassword"
    fi

    if [ -n "$DEFAULT_PASS" ]; then
        if mysql -uroot -p"$DEFAULT_PASS" -e 'bruh' 2>&1 >/dev/null | grep -v '\[Warning\]' | grep -q 'bruh'; then
            echo -e "${RED}Can login with root:$DEFAULT_PASS${NC}\n"
            SQLCMD="mysql -uroot -p$DEFAULT_PASS"
        fi
    fi

    if [ -z "$SQLCMD" ]; then
        SQL_AUTH=0
    fi
    
    if [ "$SQL_AUTH" = 1 ]; then
        echo "SQL User Information"
        echo -e "${ORAG}$( DPRINT $SQLCMD -t -e 'select user,host,plugin,authentication_string from mysql.user where password_expired="N";' )${NC}\n" 
        DATABASES=$( DPRINT $SQLCMD -t -e 'show databases' | grep -vE '^\|\s(mysql|information_schema|performance_schema|sys|test)\s+\|' )
        if [ -n "$DATABASES" ]; then
            echo "SQL Databases"
            echo -e "${ORAG}$DATABASES${NC}\n"
        fi
    else
        echo "Cannot login with weak creds or default credentials"
    fi
}
if checkService "$SERVICES"  'mysql' | grep -qi "is on this machine"; then 
    MYSQL=true
    checkService "$SERVICES"  'mysql' 
    sql_test
fi

if checkService "$SERVICES"  'mariadb' 'mysql' | grep -qi "is on this machine"; then 
    MARIADB=true
    checkService "$SERVICES"  'mariadb' 'mysql'
    sql_test
fi

if checkService "$SERVICES"  'postgres' | grep -qi "is on this machine" ; then
    POSTGRESQL=true
    checkService "$SERVICES" 'postgres' || checkService "$SERVICES" 'postgres' 'postmaster'
    PSQLHBA=$( grep -REvh '(#|^\s*$|replication)' $( DPRINT find /etc/postgresql/ /var/lib/pgsql/ /var/lib/postgres* -name pg_hba.conf | head -n 1 ) )
    echo -e "PostgreSQL Authentication Details\n"
    echo -e "${ORAG}$PSQLHBA${NC}\n"

    if DPRINT psql -U postgres -c '\q'; then
        AUTH=1
        DB_CMD=" psql -U postgres -c \l "
    elif DPRINT sudo -u postgres psql -c '\q'; then
        AUTH=1
        DB_CMD=" sudo -u postgres psql -c \l "
    fi
    if [ "$AUTH" = 1 ]; then
        DATABASES="$( DPRINT $DB_CMD | grep -vE '^\s(postgres|template0|template1|\s+)\s+\|' | head -n -2 )"
        if [ "$( echo "$DATABASES" | wc -l )" -gt 2 ]; then
            echo "PostgreSQL Databases"
            echo -e "${ORAG}$DATABASES${NC}\n"
        fi
    fi
fi

# idk about any of these
if checkService "$SERVICES"  'python' | grep -qi "is on this machine"; then checkService "$SERVICES"  'python' ; PYTHON=true; fi
if checkService "$SERVICES"  'dropbear' | grep -qi "is on this machine"; then checkService "$SERVICES"  'dropbear' ; DROPBEAR=true; fi
if checkService "$SERVICES"  'php' | grep -qi "is on this machine"; then checkService "$SERVICES"  'php' ; PHP=true; fi
if checkService "$SERVICES"  'vsftpd' | grep -qi "is on this machine"; then checkService "$SERVICES"  'vsftpd' ; VSFTPD=true; fi
if checkService "$SERVICES"  'pure-ftpd' | grep -qi "is on this machine"; then checkService "$SERVICES"  'pure-ftpd' ; PUREFTPD=true; fi
if checkService "$SERVICES"  'proftpd' | grep -qi "is on this machine"; then checkService "$SERVICES"  'proftpd' ; PROFTPD=true; fi
if checkService "$SERVICES"  'httpd' | grep -qi "is on this machine"; then checkService "$SERVICES"  'httpd' ; HTTPD=true; fi
if checkService "$SERVICES"  'xinetd' | grep -qi "is on this machine"; then checkService "$SERVICES"  'xinetd' ; XINETD=true; fi
if checkService "$SERVICES"  'inetd' | grep -qi "is on this machine"; then checkService "$SERVICES"  'inetd' ; INETD=true; fi
if checkService "$SERVICES"  'tftpd' | grep -qi "is on this machine"; then checkService "$SERVICES"  'tftpd' ; TFTPD=true; fi
if checkService "$SERVICES"  'atftpd' | grep -qi "is on this machine"; then checkService "$SERVICES"  'atftpd' ; ATFTPD=true; fi
if checkService "$SERVICES"  'smbd' | grep -qi "is on this machine"; then checkService "$SERVICES"  'smbd' ; SMBD=true; fi
if checkService "$SERVICES"  'nmbd' | grep -qi "is on this machine"; then checkService "$SERVICES"  'nmbd' ; NMBD=true; fi
if checkService "$SERVICES"  'snmpd' | grep -qi "is on this machine"; then checkService "$SERVICES"  'snmpd' ; SNMPD=true; fi
if checkService "$SERVICES"  'ypbind' | grep -qi "is on this machine"; then checkService "$SERVICES"  'ypbind' ; YPBIND=true; fi
if checkService "$SERVICES"  'rshd' | grep -qi "is on this machine"; then checkService "$SERVICES"  'rshd' ; RSHD=true; fi
if checkService "$SERVICES"  'rexecd' | grep -qi "is on this machine"; then checkService "$SERVICES"  'rexecd' ; REXECD=true; fi
if checkService "$SERVICES"  'rlogin' | grep -qi "is on this machine"; then checkService "$SERVICES"  'rlogin' ; RLOGIN=true; fi
if checkService "$SERVICES"  'telnet' | grep -qi "is on this machine"; then checkService "$SERVICES"  'telnet' ; TELNET=true; fi
if checkService "$SERVICES"  'squid' | grep -qi "is on this machine"; then checkService "$SERVICES"  'squid' ; SQUID=true; fi

echo -e "\n${GREEN}##########################End of Output#########################${NC}"