#!/bin/sh
if id | grep -q "uid=0"; then
  :
else
  echo "You must run this script as root!"
  exit
fi

if uname -a | grep "BSD"; then
  printf "\033[31mThis is BSD.\033[00m\n\n"
  cd BSD
elif uname -a | grep "Sun"; then
  printf "\033[32mThis is Solaris. Good luck T-T\033[00m\n\n"
  exit
else
  printf "\033[33mThis is standard Linux, have fun!\033[00m\n\n"
fi

printf "\033[01mBegin Blackout\033[00m\n"
./blackout.sh
printf "\033[01mChanging passwords\033[00m\n"
./pass.sh
printf "You should \033[01msave these passwords\033[00m and update the score checker! Say something when you are ready to continue: "
read ans
printf "\033[01mBegin hardening\033[00m of users\n"
./fixUsers.sh
printf "Here are your final configurations. Good luck hardening!\n"
