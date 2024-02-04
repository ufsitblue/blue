# Change root passwords.
# TODO: change general user passwords
# TODO: generate CSVs for the password changes according to the specified format (https://anonymfile.com/6Q6D/seccdc-24-team-packet.pdf)


if [[ -z $ROOT_PW ]]; then
    #ROOT_PW=$(echo "$(date +%N)$RANDOM" | sha256sum | cut -d" " -f1 | cut -c -20)
    # Uses /dev/urandom to make passwords more secure
    ROOT_PW=$(head -c 100 /dev/urandom | tr -dc 'a-zA-Z0-9@#$%&!?:*-+=' | cut -c1-23)
fi

echo "root:$ROOT_PW" | chpasswd
echo "[+] Changed root password to $ROOT_PW"
