"""
Script to change passwords on Linux machines

Copyright (c) 2024 Yuliang Huang
"""
import argparse
import secrets
import socket
import subprocess
import sys
import os
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
            subprocess.run(["id", username], check=True)
        except subprocess.CalledProcessError:
            user_exists = False
        if user_exists:
            word_password = "-".join((w.lower() for w in genpass.genpass()))
            insert_index = secrets.randbelow(len(word_password))
            password = word_password[:insert_index] + str(secrets.randbelow(10)) + word_password[insert_index:]
            subprocess.run(["chpasswd"], input=(username + ":" + password).encode("utf-8"))
        output_string += os.environ["CUSTOM_HOSTNAME"] + "-ssh2," + username + "," + password + "\n"

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
