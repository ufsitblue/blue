#!/bin/sh
size=$(wc -l WORDLIST.TXT | awk '{print $1}')
genword() {
  echo $(head -n $(expr 1 + $(od -A n -t d -N 2 /dev/urandom) % $size) WORDLIST.TXT | tail -n 1)
}
genpass() {
  pass=$(genword)
  for i in $(seq 1 5)
  do temp=$(genword)
    pass="$pass""0""$temp"
  done
  echo "$pass"
}
out=""
for user in $(egrep -v '#|bin/nologin|bin/false' /etc/passwd | awk -F: '{print $1}')
do pass=$(genpass)
  echo "$pass" | pw usermod -n "$user" -h 0
  out="$out\n$user: $pass"
done
printf "$out\n"
