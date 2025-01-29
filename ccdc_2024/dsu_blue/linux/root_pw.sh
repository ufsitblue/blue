# Change root passwords.

if [[ -z $ROOT_PW ]]; then
    ROOT_PW=$(echo "$(date +%N)$RANDOM" | sha256sum | cut -d" " -f1 | cut -c -12)
fi

echo "root:$ROOT_PW" | chpasswd
echo "[+] Changed root password to $ROOT_PW"
