#Write wrapper to handle ssh connections? Replacing paramiko?
import subprocess;
import time;
from datetime import datetime
def run_ssh_command(host,password, cmd, print_output=True):
    try:
        # Check if paramiko is installed
        try:
            import paramiko
            use_paramiko = True
        except ImportError:
            use_paramiko = False

        if use_paramiko:
            # Use paramiko for SSH connection
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            # Assuming you have key-based authentication, you might need to modify this part if using passwords
            ssh.connect(host,username="root",password=password)
            stdin, stdout, stderr = ssh.exec_command(cmd)

            # Capture the output
            output = stdout.read().decode('utf-8')

            # Print or return the output
            if print_output:
                print("Output:")
                print(output)
                log_command_execution(cmd,stdout.read().decode('utf-8'),host)
            else:
                log_command_execution(cmd,stdout.read().decode('utf-8'),host)
                return output

            # Print any errors
            if stderr:
                print("Errors:")
                print(stderr.read().decode('utf-8'))

            # Close the SSH connection
            ssh.close()
        else:
            # Use subprocess to run the SSH command
            process = subprocess.Popen(
                ["sshpass", "-p", password, "ssh", host,"-l","root", cmd],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True  # For Python 3.6 and earlier
            )

            # Capture the output and errors
            stdout, stderr = process.communicate()

            # Print or return the output
            output = stdout
            if print_output:
                print("Output:")
                print(output)
                log_command_execution(cmd,stdout,host)
            else:
                log_command_execution(cmd,stdout,host)
                return output

            # Print any errors
            if stderr:
                print("Errors:")
                print(stderr)

    except Exception as e:
        print(f"Error: {e}")

def push_to_scp(host, cmd, file, path):
    try:
        # Use subprocess to run the SCP command
        scp_command = f"scp {file} {host}:{path}"
        process = subprocess.Popen(
            scp_command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True  # For Python 3.7 and later
        )

        # Capture the output and errors
        stdout, stderr = process.communicate()

        # Print the output
        print("Output:")
        print(stdout)

        # Print any errors
        if stderr:
            print("Errors:")
            print(stderr)

    except Exception as e:
        print(f"Error: {e}")


import subprocess

def pull_from_scp(host, remote_file, local_path):
    try:
        # Use subprocess to run the SCP command for pulling
        scp_command = f"scp {host}:{remote_file} {local_path}"
        process = subprocess.Popen(
            scp_command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True  # For Python 3.7 and later
        )

        # Capture the output and errors
        stdout, stderr = process.communicate()

        # Print the output
        print("Output:")
        print(stdout)

        # Print any errors
        if stderr:
            print("Errors:")
            print(stderr)

    except Exception as e:
        print(f"Error: {e}")



def log_command_execution(command, result, box):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open('Command_Log.txt', 'a') as log_file:
        log_file.write(f"[{timestamp}] Box: {box}\n")
        log_file.write(f"Command: {command}\n")
        log_file.write(f"Result:\n{result}\n")
        log_file.write("=" * 40 + "\n\n")
