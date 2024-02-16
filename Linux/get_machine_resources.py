import os
import psutil
import socket
import sys

import mattermost

def main(argv: list[str]) -> int:
    free_memory = str(round(psutil.virtual_memory().available / (1<<30),2)) + " GiB"
    cpus = os.cpu_count()
    hostname = socket.gethostname()
    ip_addresses = {socket.gethostbyname(socket.gethostname())}

    # Get IP address another way
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0)
    ip_address = "127.0.0.1"
    try:
        sock.connect(("10.10.10.10", 53))
        ip_address = sock.getsockname()[0]
    except:
        pass
    finally:
        sock.close()
    ip_addresses.add(ip_address)

    output_string = "Hostname: " + hostname + "\nIP addresses: " + ", ".join(ip_addresses) + \
            "\nCPUs: " + str(cpus) + "\nFree memory: " + str(free_memory)
    print(output_string)
    
    mattermost_token = mattermost.get_token()
    mmapi = mattermost.MattermostApi(mattermost_token)

    print("Press Ctrl-C now if you don't want to post to Mattermost")
    channel = mmapi.get_some_channel()

    mmapi.post_message(channel["id"], output_string)
    
    print("Information posted to Mattermost!")

if __name__ == "__main__":
    sys.exit(main(sys.argv))
