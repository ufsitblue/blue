# LOGIN AUDITING - Debian/Ubuntu/Alpine
cat /var/log/auth.log | grep -E '(Failed|Accepted) password' | wc -l

# LOGIN AUDITING - RHEL
cat /var/log/secure | grep -E '(Failed|Accepted) password' | wc -l

# FAILED LOGIN - Debian/Ubuntu/Alpine
cat /var/log/auth.log | grep 'Failed password' | wc -l

# FAILED LOGIN - RHEL
cat /var/log/secure | grep 'Failed password' | wc -l

# SUCCESSFUL LOGIN - Debian/Ubuntu/Alpine
cat /var/log/auth.log | grep 'Accepted password' | wc -l

# SUCCESSFUL LOGIN - RHEL
cat /var/log/secure | grep 'Accepted password' | wc -l

# TOP 10 ACCOUNT LOGIN ATTEMPTS - Debian/Ubuntu/Alpine
cat /var/log/auth.log | grep -E '(Failed|Accepted) password' | awk -F 'for' '{print $2}' | awk '{ if ($1 != “invalid” && $2 != “user”) { print $1 } else { print $3 } }' | sort | uniq -c | sort -nr

# TOP 10 ACCOUNT LOGIN ATTEMPTS - RHEL
cat /var/log/secure | grep -E '(Failed|Accepted) password' | awk -F 'for' '{print $2}' | awk '{ if ($1 != “invalid” && $2 != “user”) { print $1 } else { print $3 } }' | sort | uniq -c | sort -nr

# ADMIN AUDITING 
cat /etc/group | grep -E 'sudo|adm|admin|wheel' | awk -F ':' '{print $4}' | tr ',' '\n' | sort | uniq

# VALID USERS
diff /etc/passwd /root/.cache/users

