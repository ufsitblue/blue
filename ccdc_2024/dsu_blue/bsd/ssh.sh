#!/bin/bash

# secure sshd_config
echo "PubkeyAuthentication no" > ssh.txt
echo "PermitEmptyPasswords no" >> ssh.txt
echo "UseDns no" >> ssh.txt
echo "AddressFamily inet" >> ssh.txt

cat /etc/ssh/sshd_config >> ssh.txt
mv ssh.txt /etc/ssh/sshd_config

# restart
sshd -t && service sshd restart
