#!/bin/sh
# Another banger from the fabriel
# back up /etc/passwd just in case

if [ ! -z "$REVERT"  ]; then
    cp /etc/passwd.bak /etc/passwd
else
    cp /etc/passwd /etc/passwd.bak
    chmod 644 /etc/passwd.bak

    # create rbash if it doesn't exist
    if ! which rbash >/dev/null ; then
        ln -sf /bin/bash /bin/rbash
    fi

    # set rbash for non-root bash users
    if command -v bash >/dev/null ; then
        head -1 /etc/passwd > /etc/pw
        sed -n '1!p' /etc/passwd | sed 's/\/bin\/.*sh$/\/bin\/rbash/g' >> /etc/pw
        mv /etc/pw /etc/passwd
        chmod 644 /etc/passwd
    fi

    for homedir in /home/* ; do 
        echo 'PATH=""' >> $homedir/.bashrc 
        echo 'export PATH' >> $homedir/.bashrc
        if command -v apk >/dev/null; then
            echo 'export PATH' >> $homedir/.profile
        fi
    done
fi
