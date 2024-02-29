#!/bin/bash

# Check if at least one host is provided
if [ "$#" -eq 0 ]; then
    echo "Usage: $0 host1 [host2 ... hostN]"
    exit 1
fi

# Define the variables
inventory_file="$(pwd)/inventory/hosts.yaml"
linux_file="linux.yaml"
win_file="windows.yaml"
man_file="manager.yaml"
got_man=0
private_key=0
win=0
linux=0

# Read in use host file location and store it, otherwise create directory inventory if it doesn't exist
read -p "Where is your hosts file? (Blank for default: $inventory_file): " user_hosts

if [ ! "$user_hosts" = "" ]; then
   inventory_file=$user_hosts
   if [ ! -f $inventory_file ]; then
      echo "File $inventory_file does not exist"
      exit 1
   fi
else
   if [ ! -d inventory ]; then
      mkdir inventory
   fi
fi

# Create or overwrite the inventory file
echo -e "linux:" > "$linux_file"
echo -e "  hosts:" >> "$linux_file"
echo -e "windows:" > "$win_file"
echo -e "  hosts:" >> "$win_file"
echo -e "manager:" > "$man_file"
echo -e "  hosts:" >> "$man_file"
echo -e "" > $inventory_file

# Check if using private key log in

# Add each host to the inventory file with user-provided details
for host in "$@"; do
    read -p "Is '$host' a Linux or Windows host? (l/w): " os_type
    os_type=$(echo "$os_type" | tr '[:upper:]' '[:lower:]')  # Convert to lowercase
    
    case "$os_type" in
        l|linux)
	    linux=1
	    # Gets the ip, ssh username, and the password/private key
	    read -p "Enter ip address: " ip
	    read -p "Enter SSH username: " user
            # Add that infor to file no matter what
	    echo -e "    $host:" >> $linux_file
	    echo -e "      ansible_host: $ip" >> $linux_file
	    echo -e "      ansible_user: $user" >> $linux_file
     
	    read -p "Are you using private key login? (y/n): " priv
	    
	    if [ "$priv" = "y" ]; then
			private_key=1
			while true; do
				echo -e "Select a private key:\n"
				for i in "${!used_priv_keys[@]}"; do
					echo "$((i+1))) ${used_priv_keys[i]}"
				done
				echo -e "n) Enter a new private key path\n"
				read -p "Your choice (number or 'n'): " choice

				# Check if choice is a number and within the range of used keys
				if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -le "${#used_priv_keys[@]}" ] && [ "$choice" -gt 0 ]; then
					priv_path="${used_priv_keys[$((choice-1))]}"
					echo "Selected private key: $priv_path"
					break
				elif [ "$choice" = "n" ]; then
					read -e -p "Enter new private key path: " priv_path
					priv_path=$(realpath "$priv_path") # Convert to absolute path
					if [ -z "$priv_path" ]; then
						echo "Skipping private key configuration."
						break
					elif [ -f "$priv_path" ] && [ -r "$priv_path" ]; then
						echo "Private key path is valid."
						used_priv_keys+=("$priv_path") # Add the new key path to the array
						break
					else
						echo "Invalid path or file not readable. Please try again."
					fi
				else
					echo "Invalid choice. Please try again."
				fi
			done

			if [ -n "$priv_path" ]; then
				# Input information into linux yaml file
				# host="$host" ip="$ip" yq -i '.linux.hosts.[env(host)].ansible_host = env(ip)' "$linux_file"
				# host="$host" user="$user" yq -i '.linux.hosts.[env(host)].ansible_user = env(user)' "$linux_file"
				# host="$host" priv_path="$priv_path" yq -i '.linux.hosts.[env(host)].ansible_private_key_file = env(priv_path)' "$linux_file"
    				echo -e "      ansible_private_key_file: $priv_path" >> $linux_file
			fi
	    else
	       read -s -p "Enter SSH password" password
	       echo
	       
	       # Input information into linux yaml file
	       # host="$host" ip="$ip" yq -i '.linux.hosts.[env(host)].ansible_host = env(ip)' "$linux_file"
	       # host="$host" user="$user" yq -i '.linux.hosts.[env(host)].ansible_user = env(user)' "$linux_file"
	       # host="$host" password="$password" yq -i '.linux.hosts.[env(host)].ansible_password = env(password)' "$linux_file"
	       echo -e "      ansible_password: $password" >> $linux_file
	    fi

	    # Check if the current host is the wazuh manager to add it to the manager group
	    if [ $got_man -eq 0 ]; then
	       read -p "Is this the Wazuh Manager? (y/n): " ans
	       if [ $ans = "y" ]; then
		  # Only have one wazuh manager
		  got_man=1
                  echo -e "    $host:" >> $man_file
	          echo -e "      ansible_host: $ip" >> $man_file
	          echo -e "      ansible_user: $user" >> $man_file
                  
                  # Check if using private key or password for login then input the corresponding info into manager yaml
		  if [ $private_key -eq "1" ]; then
	             # host="$host" ip="$ip" yq -i '.manager.hosts.[env(host)].ansible_host = env(ip)' "$man_file"
	             # host="$host" user="$user" yq -i '.manager.hosts.[env(host)].ansible_user = env(user)' "$man_file"
	             # host="$host" priv_path="$priv_path" yq -i '.manager.hosts.[env(host)].ansible_private_key_file = env(priv_path)' "$man_file"
	             echo -e "      ansible_private_key_file: $priv_path" >> $man_file
	          else
	             # host="$host" ip="$ip" yq -i '.manager.hosts.[env(host)].ansible_host = env(ip)' "$man_file"
	             # host="$host" user="$user" yq -i '.manager.hosts.[env(host)].ansible_user = env(user)' "$man_file"
	             # host="$host" password="$password" yq -i '.manager.hosts.[env(host)].ansible_password = env(password)' "$man_file"
	             echo -e "      ansible_password: $password" >> $man_file
	          fi
	       fi
	    fi
	    echo
            ;;
        w|windows)
	    win=1
	    # Get the winrm username and password and the ip address to connect to
	    read -p "Enter winrm username: " user
            read -s -p "Enter winrm password: " password
	    echo
	    read -p "Enter ip address: " ip
	    
	    # Check if the current host is the wazuh manager and put info into the appropriate file
	    if [ $got_man -eq 0 ]; then
	       read -p "Is this the Wazuh Manager? (y/n): " ans
	       if [ $ans = "y" ]; then
		  got_man=1
		  # host="$host" ip="$ip" yq -i '.manager.hosts.[env(host)].ansible_host = env(ip)' "$man_file"
	          # host="$host" subnet="$subnet" yq -i '.manager.hosts.[env(host)].ansible_subnet = env(subnet)' "$man_file"
		  # host="$host" user="$user" yq -i '.manager.hosts.[env(host)].ansible_user = env(user)' "$man_file"
		  # host="$host" password="$password" yq -i '.manager.hosts.[env(host)].ansible_password = env(password)' "$man_file"
		  # host="$host" yq -i '.manager.hosts.[env(host)].ansible_connection = "winrm"' "$man_file" 
		  # host="$host" yq -i '.manager.hosts.[env(host)].ansible_winrm_scheme = "http"' "$man_file"
		  # host="$host" yq -i '.manager.hosts.[env(host)].ansible_port = 5985' "$man_file"
		  # host="$host" yq -i '.manager.hosts.[env(host)].ansible_winrm_transport = "ntlm"' "$man_file"
                  echo -e "    $host:" >> $man_file
		  echo -e "      ansible_host: $ip" >> $man_file
                  echo -e "      ansible_user: $user" >> $man_file
                  echo -e "      ansible_password: $password" >> $man_file
		  echo -e '      ansible_connection: "winrm"' >> $man_file
		  echo -e '      ansible_winrm_scheme: "http"' >> $man_file
                  echo -e '      ansible_port: "5985"' >> $man_file
		  echo -e '      ansible_winrm_transport = "ntlm"' >> $man_file
	       fi
	    fi

            # host="$host" ip="$ip" yq -i '.windows.hosts.[env(host)].ansible_host = env(ip)' "$win_file"
	    # host="$host" user="$user" yq -i '.windows.hosts.[env(host)].ansible_user = env(user)' "$win_file"
	    # host="$host" password="$password" yq -i '.windows.hosts.[env(host)].ansible_password = env(password)' "$win_file"
	    # host="$host" yq -i '.windows.hosts.[env(host)].ansible_connection = "winrm"' "$win_file" 
	    # host="$host" yq -i '.windows.hosts.[env(host)].ansible_winrm_scheme = "http"' "$win_file"
	    # host="$host" yq -i '.windows.hosts.[env(host)].ansible_port = 5985' "$win_file"
	    # host="$host" yq -i '.windows.hosts.[env(host)].ansible_winrm_transport = "ntlm"' "$win_file"
            echo -e "    $host:" >> $win_file
	    echo -e "      ansible_host: $ip" >> $win_file
            echo -e "      ansible_user: $user" >> $win_file
            echo -e "      ansible_password: $password" >> $win_file
	    echo -e '      ansible_connection: "winrm"' >> $win_file
	    echo -e '      ansible_winrm_scheme: "http"' >> $win_file
            echo -e '      ansible_port: "5985"' >> $win_file
	    echo -e '      ansible_winrm_transport = "ntlm"' >> $win_file
            echo
	    ;;
        *)
            echo "Invalid input. Specify 'l' for Linux or 'w' for Windows."
            exit 1
            ;;
    esac
done

if [ $win -eq 0 ]; then
    cat /dev/null > $win_file
fi

if [ $linux -eq 0 ]; then
    cat /dev/null > $linux_file
fi

if [ $got_man -eq 0 ]; then
    cat /dev/null > $man_file
fi
# Update/Append the host info into the inventory/hosts file
# yq ea '. as $item ireduce ({}; . * $item )' $inventory_file $linux_file $man_file $win_file > $inventory_file
cat $linux_file >> $inventory_file
cat $win_file >> $inventory_file
cat $man_file >> $inventory_file

# Remove intermediate files
rm "$linux_file" "$win_file" "$man_file"
echo "Ansible inventory file '$inventory_file' updated successfully."
echo
echo "Installing Ansible Packages..."
echo

# Make sure community.general is installed with ansible
if [ $(ansible-galaxy collection list | grep community\\\.general | wc -l) -eq "0" ]; then
   ansible-galaxy collection install community.general
fi

# Make sure ansible.windows is installed with ansible
if [ $(ansible-galaxy collection list | grep ansible\\\.windows | wc -l) -eq "0" ]; then
   ansible-galaxy collection install ansible.windows
fi

# Make sure ansible.posix is installed with ansible
if [ $(ansible-galaxy collection list | grep ansible\\\.posix | wc -l) -eq "0" ]; then
   ansible-galaxy collection install ansible.posix
fi

echo "Creating ansible.cfg"
echo
ansible-config init --disabled > ~/.ansible.cfg

echo "Adding Inventory to ansible.cfg"

commented_inventory_lines=$(grep -E "^[[:space:]]*[;#][[:space:]]*inventory[[:space:]]*=" ~/.ansible.cfg | wc -l)

# Check if inventory setting is commented with either ';' or '#'
if [ $commented_inventory_lines -eq 1 ]; then
   # Uncomment the inventory line and update it with the new inventory file path
   sudo sed -i "s@^[[:space:]]*[;#][[:space:]]*inventory[[:space:]]*=.*@inventory=$(echo $inventory_file)@g"  ~/.ansible.cfg
elif [ $commented_inventory_lines -eq 0 ]; then
   # Append the new inventory file path if it's not already present
   sudo sed -i "s@inventory[[:space:]]*=.*@inventory=$(echo $inventory_file)@g"  ~/.ansible.cfg
fi
