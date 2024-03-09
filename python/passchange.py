"""
Script to change passwords on Linux machines

Copyright (c) 2024 Yuliang Huang
"""
import argparse
import socket
import subprocess
import sys
sys.dont_write_bytecode = True

import genpass
import mattermost

def main(argv: list[str]) -> int:
    argparser = argparse.ArgumentParser(description="password changer for Linux")
    argparser.add_argument("usersfile", help="path to a file containing a newline-delimited list of users")
    parsedargs = argparser.parse_args()

    users_to_change_password: list[str] = []
    with open(parsedargs.usersfile, 'r') as usersfile:
        for line in usersfile:
            users_to_change_password.append(line.strip())
    
    output_string = ""

    for username in users_to_change_password:
        user_exists = True
        try:
            subprocess.call(["id", username], check=True)
        except subprocess.CalledProcessError:
            user_exists = False
        if user_exists:
            password = "-".join(genpass.genpass())
            subprocess.call(["chpasswd"], input=username + ":" + password)
        output_string += socket.gethostname() + "-ssh2," + username + "," + password + "\n"

    print("Copy and paste this text into the scoring portal: \n" + output_string)
    
    mattermost_token = mattermost.get_token()

    if mattermost_token is None:
        print("Could not get Mattermost token, not posting to Mattermost")
    else:
        mmapi = mattermost.MattermostApi(mattermost_token)
        channel = mmapi.get_some_channel()
        mmapi.post_message(channel["id"], "```\n" + output_string + "\n```")
        print("Information posted to Mattermost")

    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv))
