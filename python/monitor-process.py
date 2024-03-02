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

def main(argv: list[str]) -> int:
    argparser = argparse.ArgumentParser()
    argparser.add_argument("users", metavar="user", type=str, nargs="*", help="the usernames to kill shells of")
    argparser.add_argument("--list", action="store_true", help="list all users running a process and exit")
    argparser.add_argument("--log", help="log to the specified file in addition to printing to console")
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
    
    def printlog(message: str):
        print(message)
        if parsedarguments["log"]:
            try:
                with open(parsedarguments["log"], "a") as logfile:
                    logfile.write(message + "\n")
            except PermissionError:
                print("WARNING: Failed to log to file \"" + parsedarguments["log"] + "\", got permission denied.")

    no_shell_users = parsedarguments["users"]
    while True:
        for process in psutil.process_iter():
            try:
                executable_name = pathlib.Path(process.exe()).name
                if os.name == "nt":
                    if executable_name.lower() in shells_win:
                        printlog(process.username() + " is running " + process.exe())
                        if process.username() in no_shell_users:
                            printlog("Killed process " + str(process.pid))
                            os.kill(process.pid, signal.SIGTERM)
                else:
                    if executable_name in shells_nix:
                        printlog(process.username() + " is running " + process.exe())
                        if process.username() in no_shell_users:
                            os.kill(process.pid, signal.SIGKILL)
            except psutil.AccessDenied:
                # We aren't root/administrator. Life goes on...
                pass
        time.sleep(15)
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv))
