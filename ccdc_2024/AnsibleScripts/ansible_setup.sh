#!/bin/bash
# test
# Check if at least one host is provided
if [ "$#" -eq 0 ]; then
    echo "Usage: $0 hostname1 [hostname2 ... hostnameN]"
    exit 1
fi

# Define the variables
inventory_file="$(pwd)/inventory/hosts.yaml"
linux_file="linux.yaml"
bsd_file="bsd.yaml"
win_file="windows.yaml"
man_file="manager.yaml"
got_man=0
private_key=0
win=0
linux=0
bsd=0
os_input=0


# Read in use host file location and store it, otherwise create directory inventory if it doesn't exist
read -p "Where is your hosts file? (Blank for default: $inventory_file): " user_hosts
read -p "Are you using the same user? (y/n): " same_user
read -p "Are you using the same password? (y/n): " same_pass
if [ $same_user == "y" ]; then
  read -p "Enter the default user: " user
fi
if [ $same_pass == "y" ]; then
  read -p "Enter the default password: " password
fi

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
echo -e "bsd:" > "$bsd_file"
echo -e "  hosts:" >> "$bsd_file"
echo -e "windows:" > "$win_file"
echo -e "  hosts:" >> "$win_file"
echo -e "manager:" > "$man_file"
echo -e "  hosts:" >> "$man_file"
echo -e "" > $inventory_file

# Check if using private key log in

# Add each host to the inventory file with user-provided details
for host in "$@"; do
  os_input=0
  while [ $os_input -eq 0 ]; do
    read -p "Is '$host' a Linux, Windows, or BSD host? (l/w/b): " os_type
    os_type=$(echo "$os_type" | tr '[:upper:]' '[:lower:]')  # Convert to lowercase
    
    case "$os_type" in
        l|linux)
      os_input=1
	    linux=1
	    # Gets the ip, ssh username, and the password/private key
	    read -p "Enter ip address: " ip
      if [ $same_user == "n" ]; then
	      read -p "Enter SSH username: " user
      fi
      if [ $same_pass == "n" ]; then
        read -p "Enter SSH password: " password
      fi
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
    				echo -e "      ansible_private_key_file: $priv_path" >> $linux_file
			fi
	    else
	       # Input information into linux yaml file
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
	             echo -e "      ansible_private_key_file: $priv_path" >> $man_file
	          else
	             echo -e "      ansible_password: $password" >> $man_file
	          fi
	       fi
	    fi
	    echo
            ;;
        b|bsd)
	    bsd=1
      os_input=1
	    # Gets the ip, ssh username, and the password/private key
	    read -p "Enter ip address: " ip
      if [ $same_user == "n" ]; then
	      read -p "Enter SSH username: " user
      fi
      if [ $same_pass == "n" ]; then
        read -p "Enter SSH password: " password
      fi
            # Add that infor to file no matter what
	    echo -e "    $host:" >> $bsd_file
	    echo -e "      ansible_host: $ip" >> $bsd_file
	    echo -e "      ansible_user: $user" >> $bsd_file
     
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
				# Input information into bsd yaml file
    				echo -e "      ansible_private_key_file: $priv_path" >> $bsd_file
			fi
	    else
	       # Input information into bsd yaml file
	       echo -e "      ansible_password: $password" >> $bsd_file
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
	             echo -e "      ansible_private_key_file: $priv_path" >> $man_file
	          else
	             echo -e "      ansible_password: $password" >> $man_file
	          fi
	       fi
	    fi
	    echo
            ;;
        w|windows)
	    win=1
      os_input=1
	    # Get the winrm username and password and the ip address to connect to
	    read -p "Enter ip address: " ip
      if [ $same_user == "n" ]; then
	      read -p "Enter winrm username: " user
      fi
      if [ $same_pass == "n" ]; then
        read -p "Enter winrm password: " password
      fi
      read -p "Domain cotroller? (true or false): " controller
	    
            echo -e "    $host:" >> $win_file
	    echo -e "      ansible_host: $ip" >> $win_file
            echo -e "      ansible_user: $user" >> $win_file
            echo -e "      ansible_password: $password" >> $win_file
	    echo -e '      ansible_connection: "winrm"' >> $win_file
	    echo -e '      ansible_winrm_scheme: "http"' >> $win_file
            echo -e '      ansible_port: "5985"' >> $win_file
	    echo -e '      ansible_winrm_transport: "ntlm"' >> $win_file
      echo -e "      domain_controller: $controller" >> $win_file
      if [ "$controller" == "true" ]; then
        sed -i s/dc_ips:/"dc_ips:\n  - $ip"/g playbooks/firewall/group_vars/all.yaml
      fi
      sed -i s/domain_hosts:/"domain_hosts:\n  - $host"/g playbooks/firewall/group_vars/all.yaml
      
      echo
	    ;;
        *)
            echo "Invalid input. Specify 'l' for Linux or 'w' for Windows."
            ;;
    esac
  done
done

if [ $win -eq 0 ]; then
    cat /dev/null > $win_file
fi

if [ $linux -eq 0 ]; then
    cat /dev/null > $linux_file
fi

if [ $bsd -eq 0 ]; then
    cat /dev/null > $bsd_file
fi

if [ $got_man -eq 0 ]; then
    cat /dev/null > $man_file
fi
# Update/Append the host info into the inventory/hosts file
# yq ea '. as $item ireduce ({}; . * $item )' $inventory_file $linux_file $man_file $win_file > $inventory_file
cat $linux_file >> $inventory_file
cat $bsd_file >> $inventory_file
cat $win_file >> $inventory_file
cat $man_file >> $inventory_file

# Remove intermediate files
rm "$linux_file" "$win_file" "$man_file" "$bsd_file"
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
echo "[defaults]" > ~/.ansible.cfg
echo "gathering = smart" >> ~/.ansible.cfg
echo "fact_caching = jsonfile" >> ~/.ansible.cfg
echo "fact_caching_connection = /tmp" >> ~/.ansible.cfg
echo "inventory = $inventory_file" >> ~/.ansible.cfg
echo "forks=20" >> ~/.ansible.cfg
echo "" >> ~/.ansible.cfg
echo "" >> ~/.ansible.cfg
echo "[ssh_connection]" >> ~/.ansible.cfg
echo "ssh_args = -o ControlMaster=auto -o ControlPersist=600s" >> ~/.ansible.cfg
echo "host_key_checking = False" >> ~/.ansible.cfg

while true; do
  read -p "Enter team ip (blank for done): " ip
  if [ ! $ip == "" ]; then
    sed -i s/team_ips:/"team_ips:\n  - $ip"/g playbooks/firewall/group_vars/all.yaml
  else
    break
  fi
done
