# Change passwords.
# TODO: change user passwords in the competition doc. Right now, it's changing all users above UID 1000 (POTENTIALLY DANGEROUS)
# TODO: generate CSVs for the password changes according to the specified format (https://anonymfile.com/6Q6D/seccdc-24-team-packet.pdf)

for user in $(awk -F':' '{ if ($3 >= 1000) print $1}' /etc/passwd); do
    if [[ -z ${USER_PW} ]]; then
        # Generate a random password for each user
        USER_PW=$(head -c 100 /dev/urandom | tr -dc 'a-zA-Z0-9@#$%&!?:*-+=' | cut -c1-23)
    fi

    echo "${user}:${USER_PW}" | chpasswd
    echo "[+] Changed password for $user to ${USER_PW}"
done
