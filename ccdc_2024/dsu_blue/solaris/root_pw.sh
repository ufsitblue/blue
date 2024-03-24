#!/bin/sh

# backup /etc/shadow
cp /etc/shadow /etc/shadow1.bak
chmod 640 /etc/shadow1.bak

# change root password only
user=`getent passwd | cut -d ":" -f 1 | grep root`                                                                                                      
if test -z "$ROOT_PW"; then
    ROOT_PW=`dd if=/dev/urandom count=4 bs=1 | digest -a md5 | cut -c -10`          
    fi
    hash=`/usr/sfw/bin/openssl passwd -1 "$ROOT_PW"`                                                                                                                            

    echo "$user:$hash:::::::" > /etc/shadow  
    cat /etc/shadow1.bak | grep -v "root" | tee -a /etc/shadow

    echo "[+] Changed root password to $ROOT_PW"
    echo "[+]Old /etc/shadow stored in /etc/shadow1.bak. Delete once passwords verified to be working and uploaded to scoring engine"
