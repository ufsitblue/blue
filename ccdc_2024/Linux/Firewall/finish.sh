# Remove crontab entry
cat /dev/null > /etc/crontabs/root
cat /dev/null > /etc/crontab

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

reboot
