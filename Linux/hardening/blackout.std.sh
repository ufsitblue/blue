#!/bin/sh
if id | grep -q "uid=0"; then
  :
else
  echo "You must run this script as root!"
  exit
fi

undo() {
  sleep $1
  num=$(iptables -L INPUT --line-numbers | tail -1 | awk '{print $1}')
  iptables -D INPUT $num
  num=$(iptables -L OUTPUT --line-numbers | tail -1 | awk '{print $1}')
  iptables -D OUTPUT $num
}
block(){
  iptables -A INPUT -j DROP
  iptables -A OUTPUT -j DROP
}

iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

for ip in $(ss | tail -5 | grep ssh | awk '{print $6}' | awk -F: '{print $1}')
do iptables -A INPUT -s "$ip" -p tcp --dport 22 -j ACCEPT
iptables -A OUTPUT -d "$ip" -p tcp --sport 22 -j ACCEPT
done

#DON'T TOUCH
undo 10 &
block

echo "Say something if you are still connected:"
read connected

sleep 5
undo 300 &
block

echo "You have 5 minutes to harden your system. Please do not mess with firewall rules!"
