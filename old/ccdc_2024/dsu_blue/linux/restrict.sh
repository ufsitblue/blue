# Restrict users

# back up /etc/passwd just in case
cp /etc/passwd /etc/passwd.bak
chmod 644 /etc/passwd.bak

# create rbash if it doesn't exist
if ! which rbash >/dev/null 2>&1; then
    ln -sf /bin/bash /bin/rbash
fi

# set rbash for non-root bash users
head -1 /etc/passwd > /etc/pw
sed -n '1!p' /etc/passwd | sed 's/\/bin\/bash/\/bin\/rbash/g' >> /etc/pw
mv /etc/pw /etc/passwd
chmod 644 /etc/passwd
