# Change passwords.
passChanger=chpasswd

cat /etc/os-release | grep -i "bsd" > /dev/null
if [ $? -eq 0 ]; then
  passChanger=chpass
fi

users=""
read -p "Enter list of protected users space delimited: " special

# Change password for users
for user in $(cat /etc/passwd | grep "sh$" | cut -d ':' -f 1); do
    # Check if user exists
    echo $special | grep "$user " > /dev/null || echo $special | grep "$user$" > /dev/null
    if [ $? -ne 0 ]; then
        # Generate a random password for each user
        pword=$(head -c 100 /dev/urandom | tr -dc 'a-zA-Z0-9@$%&!?:-+=' | cut -c1-16)

        # Change password and echo to std output for use in csv file
        echo "$user:$pword" | $passChanger > /dev/null
        echo "$user,$pword"
    fi
done
echo "Passwords successfully changed.  Submit to black team"
