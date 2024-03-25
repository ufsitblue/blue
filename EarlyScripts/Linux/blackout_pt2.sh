# Remove crontab entry
cat /dev/null > /etc/crontabs/root > /dev/null
cat /dev/null > /etc/crontab > /dev/null

# Create rsyslog.d directory
mkdir -p /etc/rsyslog.d

# Add rsyslog file
cat << 'EOF' > /etc/rsyslog.d/00-iptables.conf
:msg, contains, "[DROPPED_INPUT] " /var/log/input.log
:msg, contains, "[DROPPED_OUTPUT] " /var/log/output.log
& stop
EOF

# Restart rsyslog
case $package_manager in
    "apk") rc-service rsyslog restart ;;
    "yum"|"dnf") systemctl restart rsyslog ;;
    "apt") systemctl restart rsyslog ;;
    "zypper") systemctl restart rsyslog ;;
esac
echo "Blackout finished.  Rebooting machine in 5 seconds"

sleep 5
reboot
