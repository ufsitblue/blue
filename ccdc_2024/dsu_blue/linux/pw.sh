# Non-root user password changes.

if [[ -z $PW_LOC ]]; then
    PW_LOC="/root/.pw"
fi

if [[ -z $ENACT_PW ]]; then

    # Generate new passwords for all users.
    echo "[+] Password changes for $HOSTNAME:"
    for u in $(cat /etc/passwd | grep -E "/bin/.*sh" | grep -v "root" | cut -d":" -f1); do

        # Hash the current nanosecond with a salt
        pw=$(echo "$(date +%N)$RANDOM" | sha256sum | cut -d" " -f1 | cut -c -12)

        # Print the password to the terminal
        echo "$u,$pw"
        echo "$u,$pw" >> $PW_LOC

    done

    # Lock non-shell users
    for u in $(cat /etc/passwd | grep -vE "/bin/.*sh" | cut -d":" -f1); do
        passwd -l $u >/dev/null 2>&1
        if [[ $? -ne 0 ]]; then
            echo "[-] Error locking password for $u"
        fi
    done

else

    # Execute password changes (after they are approved)
    # RHEL: If you get "chpasswd: cannot open /etc/passwd", check selinux
    for creds in $(cat $PW_LOC); do
        u=$(echo $creds | cut -d "," -f1)
        pw=$(echo $creds | cut -d "," -f2)
        echo "$u:$pw" | chpasswd
    done

    echo "[+] Enacted password changes for $HOSTNAME."

    rm $PW_LOC
    unset PW_LOC
    unset ENACT_PW

fi
