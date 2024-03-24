#!/bin/sh
# @d_tranman/Nigel Gerald/Nigerald

if [ -z "$ROOTPASS" ] && [ -z "$YOLO" ]; then
	echo "ROOTPASS is not specified and we are not in YOLO mode. Exiting to prevent lockout."
	exit 1
fi

if [ -n "$SSHUSER" ] && [ -z "$PASS" ]; then
	echo "SSHUSER is defined, but not PASS. Exiting to prevent lockout."
	exit 1
fi

if [ -z "$SSHUSER" ] && [ -n "$PASS" ]; then
	echo "PASS is defined, but not SSHUSER. Exiting to prevent lockout."
	exit 1
fi

if [ -z "$SSHUSER" ]; then
	SSHUSER="LOLNONEXISTANTSTRINGHEREBRUH" 
fi

CHANGEPASSWORD() {
	BIN=$( which chpasswd || which passwd )
	if echo "$BIN" | grep -qi "chpasswd"; then
		CMD="echo \"$1:$2\" | $BIN"
	elif echo "$BIN" | grep -qi "passwd"; then
		CMD="printf \"$2\\n$2\\n\" | $BIN $1"
	fi
	sh -c "$CMD"
}
echo "username,password"

for user in $(cat /etc/passwd | grep -E "/bin/.*sh" | cut -f1 -d':'); do
	pass=$(cat /dev/urandom | tr -dc '[:alpha:][:digit:]' | fold -w ${1:-20} | head -n 1)
	if [ -n "$YOLO" ]; then
		ROOTPASS=$(cat /dev/urandom | tr -dc '[:alpha:][:digit:]' | fold -w ${1:-20} | head -n 1)
	fi
	if [ $user = "root" ]; then
		CHANGEPASSWORD $user $ROOTPASS
		echo "$user,$ROOTPASS"
	elif [ $user = $SSHUSER ]; then
		CHANGEPASSWORD $user $PASS
		echo "$USER,$PASS"
	else
		CHANGEPASSWORD $user $pass
		echo "$user,$pass"
        fi
done
