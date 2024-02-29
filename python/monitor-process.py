import argparse
import os
import pathlib
import psutil
import signal
import sys
import time

# I definitely missed a few, but hopefully red team will be nice.
shells_nix = {"ash", "bash", "csh" "dash", "sh", "tcsh", "zsh"}
shells_win = {"cmd.exe", "powershell.exe", "conhost.exe", "windowsterminal.exe"}

def printhelp(scriptname: str):
    print("Monitors for and optionally kills shells and other suspicious activities.")
    print(scriptname + " [USERNAME_BLACKLIST]")
    print("USERNAME_BLACKLIST - The usernames to kill shells of.")

def main(argv: list[str]) -> int:
    argparser = argparse.ArgumentParser()
    argparser.add_argument("users", metavar="user", type=str, nargs="*", help="the usernames to kill shells of")
    argparser.add_argument("--list", action="store_true", help="list all users running a process and exit")
    parsedarguments = vars(argparser.parse_args())
    
    if parsedarguments["list"] is True:
        usernames = set()
        got_permission_denied = False
        for process in psutil.process_iter():
            try:
                usernames.add(process.username())
            except psutil.AccessDenied:
                got_permission_denied = True
        print("Here are the users currently running at least one process on the system.")
        if got_permission_denied:
            print("Note: We don't have permission to read the attributes of some processes, " + 
                  " maybe you aren't running as root.")
        for user in sorted(usernames):
            print(user)
        return 0
        
    no_shell_users = parsedarguments["users"]
    while True:
        for process in psutil.process_iter():
            # TODO Use pathlib to extract the last part of the path. Also grep through the command line.
            # TODO Send SIGKILL or SIGTERM with os.kill
            try:
                executable_name = pathlib.Path(process.exe()).name
                if os.name == "nt":
                    if process.username() in no_shell_users and executable_name.lower() in shells_win:
                        os.kill(process.pid, signal.SIGTERM)
                else:
                    if process.username() in no_shell_users and executable_name in shells_nix:
                        os.kill(process.pid, signal.SIGKILL)
                print(process.username() + " is running " + process.exe())
            except psutil.AccessDenied:
                # We aren't root/administrator. Life goes on...
                pass
        time.sleep(15)
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv))
