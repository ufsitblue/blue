# Change passwords.
bsd=0

cat /etc/os-release | grep -i "bsd" > /dev/null
if [ $? -eq 0 ]; then
  bsd=1
fi

users=""
read -p "Enter list of protected users space delimited: " special
valid_shells=$(cat /etc/shells | grep -v "^#" | awk -F/ '{print $NF}' | tr '\n' '|')
valid_shells="${valid_shells%|}"  # Remove the trailing pipe

if [ $bsd -eq 1 ]; then
  # Iterate through users with valid shells
  while IFS=: read -r user _ _ _ _ _ shell; do
    shell_filename=$(basename "$shell")                      
    if echo "$shell_filename" | grep -E "$valid_shells" > /dev/null; then
      echo $special | grep "$user " > /dev/null || echo $special | grep "$user\$" > /dev/null
      if [ $? -ne 0 ]; then
        new_password=$(openssl rand -base64 12 | tr -d '\n' | tr -d '/')
        encoded_password=$(echo -n "$new_password" | openssl passwd -6 -stdin)
        chpass -p $encoded_password $user >/dev/null 2>&1
    
        if [ $? -eq 0 ]; then
          echo "$user,$new_password"
        else
          echo "Failed to change password for $user"
        fi
      fi
    fi
  done < /etc/passwd
else
  # Iterate through users with valid shells
  while IFS=: read -r user _ _ _ _ _ shell; do
    shell_filename=$(basename "$shell")                      
    if echo "$shell_filename" | grep -E "$valid_shells" > /dev/null; then
      echo $special | grep "$user " > /dev/null || echo $special | grep "$user\$" > /dev/null
      if [ $? -ne 0 ]; then
        # Generate a random password for each user
        pword=$(head -c 200 /dev/urandom | tr -dc 'a-zA-Z0-9@$%&!?:+-=' | cut -c1-16)

        # Change password and echo to std output for use in csv file
        echo "$user:$pword" | chpasswd > /dev/null
        echo "$user,$pword"
      fi
    fi
  done < /etc/passwd
fi
echo "Passwords successfully changed.  Submit to black team"
