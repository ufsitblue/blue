#!/bin/sh
if id | grep -q "uid=0"; then
  :
else
  echo "You must run this script as root!"
  exit
fi
query() {
  printf "User \033[01m$1\033[00m has \033[01m$2\033[00m. Should we \033[01m$3\033[00m? [y | n]   "
  read response
  case "$response" in
    y) return 0;;
    n) return 1;;
  esac
}
fixUser() {
  case "$2" in
    U) if query "$1" "unkown user" "lock account"; then
        pw lock "$1"
       else
        :
       fi;;
    R) if query "$1" "UID=0" "set UID to GID"; then
        gid=$(grep "$1:" /etc/passwd | awk -F: '{print $4}')
        pw usermod "$1" -u "$gid"
       else
        :
       fi;;
    G) if query "$1" "sudoers group" "remove from extra groups"; then
        pw usermod "$1" -G "$1"
       else
        :
       fi;;
    S) if query "$1" "in sudoers file" "remove user from /etc/sudoers"; then
        for n in $(grep -n -v "#" /etc/sudoers | grep "$1" | awk '{print $1}'); do
          sed -i '$nd' /etc/sudoers
        done
       else
        :
       fi;;
    L) if query "$1" "can login" "set shell to /bin/false"; then
        pw usermod "$1" -s "/bin/false"
       else
        :
       fi;;
    N) if query "$1" "can authenticate without a password" "add x to /etc/passwd"; then
         pass=$(grep "^$1:" /etc/passwd | awk -F: '{print $2}')
         sed "s/$1:$pass:/$1:x:/" /etc/passwd
       else
        :
       fi;;
    C) if query "$1" "an active connection" "kill the connection"; then
         echo "Do it yourself!"
       else
        :
       fi;;
    H) if query "$1" "home directory" "nuke the directory"; then
        rm -rf "/home/$1"
       else
        :
       fi;;
    K) if query "$1" "authorized_keys SSH" "disable the keys"; then
        mv "/home/$1/.ssh/authorized_keys" "/home/$1/.ssh/author1zed_keys"
       else
        :
       fi;;
  esac
}
./listUsersPlain.sh > userList.txt
size=$(grep -n n userList.txt | tail -1 | awk -F: '{print $1}')
line=1
while [ $line -lt $size ]; do
  next=$(($line+1))
  head "-$next" userList.txt | tail -1 > line.txt
  user=$(awk '{print $2}' line.txt)
  U=$(awk '{print $1}' line.txt)
  if [ "$U" = "Y" ]; then
    fixUser "$user" "U"
  else
    :
  fi
  R=$(awk '{print $3}' line.txt)
  if [ "$R" = "Y" ]; then
    fixUser "$user" "R"
  else
    :
  fi
  G=$(awk '{print $4}' line.txt)
  if [ "$G" = "Y" ]; then
    fixUser "$user" "G"
  else
    :
  fi
  S=$(awk '{print $5}' line.txt)
  if [ "$S" = "Y" ]; then
    fixUser "$user" "S"
  else
    :
  fi
  L=$(awk '{print $6}' line.txt)
  if [ "$L" = "Y" ]; then
    fixUser "$user" "L"
  else
    :
  fi
  N=$(awk '{print $7}' line.txt)
  if [ "$N" = "Y" ]; then
    fixUser "$user" "N"
  else
    :
  fi
  C=$(awk '{print $8}' line.txt)
  if [ "$C" = "Y" ]; then
    fixUser "$user" "C"
  else
    :
  fi
  H=$(awk '{print $9}' line.txt)
  if [ "$H" = "Y" ]; then
    fixUser "$user" "H"
  else
    :
  fi
  K=$(awk '{print $10}' line.txt)
  if [ "$K" = "Y" ]; then
    fixUser "$user" "K"
  else
    :
  fi
  line=$(($line+1))
done
