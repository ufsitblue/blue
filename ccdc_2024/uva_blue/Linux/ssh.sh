#!/bin/sh

sys=$(command -v service || command -v systemctl)

sed -i -E 's/(#PubkeyAuthentication yes|PubkeyAuthentication yes)/PubkeyAuthentication no/g' /etc/ssh/sshd_config

if [[ -z $sys ]]; then
  RC="/etc/rc.d/sshd"
  $RC restart
else
  $sys restart ssh || $sys ssh restart || $sys restart sshd || $sys sshd restart 
fi
