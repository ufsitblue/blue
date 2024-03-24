#!/bin/sh

if [ -z "$ROOTPASS" ]; then
    echo "One or more variables are empty. Exiting to prevent lockout."
    exit 1
fi
echo "username,password"
for user in $(cat /etc/passwd | grep -E "/bin/.*sh" | cut -f1 -d':'); do
        pass=$(cat /dev/urandom | tr -dc '[:alpha:][:digit:]' | fold -w ${1:-20} | head -n 1)
	if [ $user = "root" ]; then
                echo $user:$ROOTPASS | chpasswd
                echo "$user,$ROOTPASS"
	elif [ $user = $USER ]; then
		echo $USER:$PASS | chpasswd
		echo "$USER,$PASS"
	else
        	echo $user:$pass | chpasswd
		echo "$user,$pass"
        fi
done
