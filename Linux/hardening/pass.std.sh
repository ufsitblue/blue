#!/bin/sh
if id | grep -q "uid=0"; then
  :
else
  echo "You must run this script as root!"
  exit
fi
gen() {
  echo "$(shuf -n 5 WORDLIST.TXT | paste -sd '0' -)"
}
out=""
for user in $(grep -Ev 'bin/nologin|bin/false|sync|blackteam' /etc/passwd | awk -F: '{print $1}')
do pass=$(gen)
(echo $pass; echo $pass) | passwd $user
out="$out\n$user: $pass"
done
printf "$out\n"
