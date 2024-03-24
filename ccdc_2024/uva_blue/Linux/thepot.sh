# Creating a honey pot

touch /var/log/honeypot; chmod 722 /var/log/honeypot; touch /bin/thepot; chmod +x /bin/thepot

cat << 'EOF' > /bin/thepot
#!/bin/bash
echo "Caught one boys!" >> /var/log/honeypot
ri(){
    echo -n "root@$HOSTNAME:~# "
    read i; if [ -n "$i" ]; then
      echo "-bash: $i: command not found"
      echo "$(date +"%A %r") -- $i" >> /var/log/honeypot
    fi; ri
}
trap "ri" SIGINT SIGTSTP exit; ri
EOF