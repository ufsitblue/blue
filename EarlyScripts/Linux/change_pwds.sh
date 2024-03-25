# Change passwords.
bsd=0

cat /etc/os-release | grep -i "bsd" > /dev/null
if [ $? -eq 0 ]; then
  bsd=1
fi

users=""
read -p "Enter list of protected users space delimited: " special

if [ $bsd -eq 1 ]; then
  for user in $(cat /etc/passwd | grep "sh$" | cut -d ':' -f 1); do
    new_password=$(openssl rand -base64 12)
    echo "$user:$new_password" | chpass
    
    if [ $? -eq 0 ]; then
      echo "$user,$new_password"
    else
      echo "Failed to change password for $user"
    fi
  done
else
  for user in $(cat /etc/passwd | grep "sh$" | cut -d ':' -f 1); do
    # Check if user is not special
    echo $special | grep "$user " > /dev/null || echo $special | grep "$user$" > /dev/null
    if [ $? -ne 0 ]; then
      # Generate a random password for each user
      pword=$(head -c 200 /dev/urandom | tr -dc 'a-zA-Z0-9@$%&!?:+-=' | cut -c1-16)

      # Change password and echo to std output for use in csv file
      echo "$user:$pword" | $passChanger > /dev/null
      echo "$user,$pword"
    fi
  done
fi
echo "Passwords successfully changed.  Submit to black team"
