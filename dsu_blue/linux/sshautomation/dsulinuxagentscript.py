import os
import yaml
from wrapper import *
from datetime import datetime
from utils.iptables import genFirewall
boxes = {}
config_path = 'config.yml'
with open(config_path, 'r') as file:
        data = yaml.safe_load(file)

def Root_Password_Changes(box):
    root_password = boxes[box][1]
    default_password = boxes[box][0]
    command = f'passwd root {root_password}'
    run_ssh_command(box,default_password,command)

def User_Password_Changes(box):
    user_password = boxes[box][2]
    default_password = boxes[box][0]
    command = f'for u in $(cat /etc/passwd | grep -v ^root: | cut -d: -f1); do echo "$u:{user_password}" | chpasswd; done'
    run_ssh_command(box,default_password,command)


def files_to_backup(box):
    files_to_backup_entry = data.get('files_to_backup', [])
    default_password = boxes[box][0]
    for file in files_to_backup_entry:
        command = f'cp {file} /root/{file}'
        run_ssh_command(box,default_password,command)


def firewall_stuff(box):
     default_password = boxes[box][0]
     command = "ss -naH4"
     stdout = run_ssh_command(box,default_password,command,False)
     bashscript = genFirewall(stdout)
     print(bashscript)
     #execute_BashScript("")


def audit_Users(box):
    command = "grep -E '/bash$|/sh$' /etc/passwd"
    default_password = boxes[box][0]
    stdout = run_ssh_command(box,default_password,command,False)
    users_data = stdout
    section_header = f"=== {box} ==="
    data_to_write = f"{section_header}\n{users_data}\n\n"
    with open('Audited_Users.txt', 'a') as file:
        file.write(data_to_write)



def change_SSH_Settings(box):
    #Maybe move to yml undecided atm
    ssh_commands = [
    "sed -i '1s;^;PermitRootLogin yes\n;' /etc/ssh/sshd_config",
    "sed -i '1s;^;PubkeyAuthentication no\n;' /etc/ssh/sshd_config",
    "sed -i '1s;^;UseDNS no\n;' /etc/ssh/sshd_config",
	"sed -i '1s;^;PermitEmptyPasswords no\n;' /etc/ssh/sshd_config",
	"sed -i '1s;^;AddressFamily inet\n;' /etc/ssh/sshd_config"
    # Add more commands as needed
]
    
    for command in ssh_commands:
        default_password = boxes[box][0]
        run_ssh_command(box,default_password,command)


def modify_php_settings(box):
    php_settings_entry = data.get('php_settings', {})
    for setting, value in php_settings_entry.items():
        command = f"echo '{setting} = {value}' >> /etc/php.ini"
        run_ssh_command(command)

def change_sysctl_settings(box):
    sysctl_settings_entry = data.get('sysctl_settings', {})
    default_password = boxes[box][0]
    for setting, value in sysctl_settings_entry.items():
        command = f"echo '{setting} = {value}' >> /etc/sysctl.d/sysctl.conf"
        run_ssh_command(box,default_password,command)
        command="sysctl -p"
        run_ssh_command(box,default_password,command)



def run_single_command(box,cmd):
    run_ssh_command(cmd,box)

def execute_BashScript(script, box):
    default_password = boxes[box][0]
    try:
        with open(script, 'r') as bash_script:
            # Read the entire script into a string
            script_content = bash_script.read()

            # Execute the entire script
            run_ssh_command(box,default_password,script)



    except Exception as e:
        print(f"Error: {e}")
def enumerate(box):
    #WIP
    print("enum")

def fix_pam(box):
    #WIP
    print("pam")

def generate_PCR(box):
    command = "grep -E '/bash$|/sh$' /etc/passwd"
    default_password = boxes[box][0]
    changed_password = boxes[box][2]
    stdout = run_ssh_command(box,default_password,command,False)
    users_data = stdout
    users_data = users_data.split(":")[0]
    pcr = ""
    for line in users_data:
        line += ",{changed_password}"
        pcr+=line
    print(pcr)





functions = [audit_Users,Root_Password_Changes,User_Password_Changes,files_to_backup,firewall_stuff,execute_BashScript,change_SSH_Settings,modify_php_settings,change_sysctl_settings,run_single_command]
def exec_function(function_number):
     for line in open("boxes.conf"):
        if "#" not in line:
            components = line.strip().split(',')
            ip_address = components[0]
            default_password = components[1]
            root_password = components[2]
            user_password = components[3]
            boxes[ip_address]=(default_password,root_password,user_password)
            functions[function_number](ip_address)



def main():
    # Read the YAML data from a file
    config_path = 'config.yml'
    with open(config_path, 'r') as file:
        data = yaml.safe_load(file)

    # Display menu options
    print("\nSelect an option:")
    print("1. Audit Users")
    print("2. Root Password Changes")
    print("3. User Password Changes")
    print("4. Files Backup")
    print("5. Firewall Stuff")
    print("6. Execute Bash Script")
    print("7. Change SSH Settings")
    print("8. Modify PHP Settings")
    print("9. Change Sysctl Settings")
    print("10. Run Single Command")
    print("0. Exit")
    option = input("Enter the option number: ")
    if(int(option) > 0 and int(option) <= 10):
        exec_function(int(option)-1)
