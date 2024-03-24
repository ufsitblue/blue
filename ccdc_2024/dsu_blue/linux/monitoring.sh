# Set up auditd

apt install auditd -qy >/dev/null

ad=/etc/audit/rules.d/audit.rules
echo "-w /etc/ -p wa -k etc" >> ad
echo "-w /tmp/ -p wx -k tmp" >> ad
echo "-w /dev/shm -p wx -k shm" >> ad
echo "-w /home -p wa -k home" >> ad
echo "-w /root -p rwa -k root" >> ad

# Set up syslog
