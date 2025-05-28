#!/bin/sh
if id | grep -q "uid=0"; then
  :
else
  echo "You must run this script as root!"
  exit
fi
user_check() {
  if grep -q "^$1" admUsers.txt; then
    out="N "
  elif grep -q "^$1" regUsers.txt; then
    out="N "
  elif grep -q "^$1" nedUsers.txt; then
    out="N "
  elif grep -q "^$1" mehUsers.txt; then
    out="Y "
  else
    out="Y "
  fi

  out="$out$1"
  for i in $(seq ${#1} 27); do
    out="$out "
  done
  out="$out"
  if [ "$2" = "0" ]; then
    out="$out Y"
  else
    out="$out N"
  fi
  if grep 'sudo\|wheel\|adm\|docker\|dial' /etc/group | grep -q "$1"; then
    out="$out Y"
  else
    out="$out N"
  fi
  if [ -f "/etc/sudoers" ] && grep -v "#" /etc/sudoers | grep -q "$1"; then
    out="$out Y"
  else
    out="$out N"
  fi

  out="$out"
  if echo "$3" | grep -v "bin/false" | grep -q -Ev "bin/nologin"; then
    out="$out Y"
  else
    out="$out N"
  fi
  if [ "$4" = "xx" ] || [ "$4" = "*x" ]; then
    out="$out N"
  else
    out="$out Y"
  fi
  if w | awk '{print $1}' | grep -q "$1"; then
    out="$out Y"
  else
    out="$out N"
  fi

  out="$out"
  if [ -d "/home/$1" ]; then
    out="$out Y"
  else
    out="$out N"
  fi
  if [ -f "/home/$1/.ssh/authorized_keys" ]; then
    out="$out Y"
  else
    out="$out N"
  fi
  out="$out"
  printf "$out\n"
}

output=""
printf "Username --------------------  R G S L N C H K\n"
grep -v "#" /etc/passwd | awk -F: '{print $1" "$2"x "$3" "$7"/"}' | (while read -r N X U L ; do
  user_check "$N" "$U" "$L" "$X"
done)
printf "$output"
