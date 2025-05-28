#!/bin/sh
for u in $(getent passwd | grep -v "root" | cut -d ":" -f1); do
    p=`tr -dc A-Za-z0-9 </dev/urandom | head -c 13 ; echo ''`
        echo "$p" | pw mod user $u -h 0 2>/dev/null
            echo "$u:$p"
            done
            -bash-4.3# cat root_pw.sh 
            #!/bin/sh

            # change root password only
            set u=`getent passwd | cut -d ":" -f 1 | grep root`                                                                                                      
            echo "$ROOT_PW" | pw mod user $u -h 0


            echo "[+] Changed root password to $ROOT_PW"
