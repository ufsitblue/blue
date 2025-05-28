#!/bin/sh
if id | grep -q "uid=0"; then
  :
else
  echo "You must run this script as root!"
  exit
fi
user_check() {
  if grep -q "^$1" admUsers.txt; then
    out="\033[36m"
  elif grep -q "^$1" regUsers.txt; then
    out="\033[32m"
  elif grep -q "^$1" nedUsers.txt; then
    out="\033[37m"
  elif grep -q "^$1" mehUsers.txt; then
    out="\033[33m"
  else
    out="\033[31m"
  fi

  out="$out$1\033[00m"
  for i in $(seq ${#1} 29); do
    out="$out "
  done
  out="$out\033[41m"
  if [ "$2" = "0" ]; then
    out="$out X"
  else
    out="$out  "
  fi
  if grep 'sudo\|wheel\|adm\|docker\|dial' /etc/group | grep -q "$1"; then
    out="$out X"
  else
    out="$out  "
  fi
  if [ -f "/etc/sudoers" ] &&  grep -v "#" /etc/sudoers | grep -q "$1"; then
    out="$out X"
  else
    out="$out  "
  fi

  out="$out\033[43m"
  if echo "$3" | grep -v "bin/false" | grep -q -Ev "bin/nologin"; then
    out="$out X"
  else
    out="$out  "
  fi
  if [ "$4" = "xx" ] || [ "$4" = "*x" ]; then
    out="$out  "
  else
    out="$out X"
  fi
  if w | awk '{print $1}' | grep -q "$1"; then
    out="$out X"
  else
    out="$out  "
  fi

  out="$out\033[42m"
  if [ -d "/home/$1" ]; then
    out="$out X"
  else
    out="$out  "
  fi
  if [ -f "/home/$1/.ssh/authorized_keys" ]; then
    out="$out X"
  else
    out="$out  "
  fi
  out="$out\033[00m"
  printf "$out\n"
}

printf "\033[01mUsername -------------------- \033[41m R G S\033[43m L N C\033[42m H K\033[00m\n"
grep -v "#" /etc/passwd | awk -F: '{print $1" "$2"x "$3" "$7"/"}' | (while read -r N X U L ; do
  user_check "$N" "$U" "$L" "$X"
done)
