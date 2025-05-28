"""
Changes passwords automatically on Windows machines
"""

import argparse
import pathlib
import random
import subprocess
import sys
import typing

def main(argv: list[str]) -> int:
    argparser: argparse.ArgumentParser = argparse.ArgumentParser("Changes passwords for Windows machines")
    argparser.add_argument("--users-file", "-u", default=pathlib.Path("users.txt"), type=pathlib.Path,
            help="Override the default users file \"users.txt\"")
    argparser.add_argument("--wordlist-file", "-w", default=pathlib.Path("wordlist.txt"), type=pathlib.Path,
            help="Override the default wordlist file \"wordlist.txt\"")
    parsedargs: dict[str, typing.Any] = vars(argparser.parse_args(argv[1:]))
    
    wordlist: list[str] = []
    with open(str(parsedargs["wordlist_file"])) as wordlist_file:
        for wordlist_word in wordlist_file:
            wordlist.append(wordlist_word.strip())
    
    password_lines_to_print: list[str] = []
    failed_usernames: list[str] = []
    print("Setting passwords...")
    with open(str(parsedargs["users_file"])) as users_file:
        for username in users_file:
            username = username.strip()
            password: str = username + ":" + "1".join(random.choices(wordlist, k=4))
            password_change_command = subprocess.run(["net", "user", username, password])
            if password_change_command.returncode == 0:
                password_lines_to_print.append(username + ":" + password)
            else:
                failed_usernames.append(username)
    
    print("Here are the changed credentials:")
    for password_line in password_lines_to_print:
        print(password_line)

    if len(failed_usernames) > 0:
        print("WARNING: Password change failed for the following usernames: " + 
              ", ".join(failed_usernames))

    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv))
