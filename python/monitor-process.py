"""
Scriptto get the processes running on a system.

Copyright (c) 2024 Yuliang Huang, UFSIT
"""

import argparse
import datetime
import json
import os
import pathlib
import psutil
import signal
import socket
import sqlite3
import sys
import time

sys.dont_write_bytecode = True

import mattermost

# I definitely missed a few, but hopefully red team will be nice.
shells_nix = {"ash", "bash", "csh" "dash", "sh", "tcsh", "zsh"}
shells_win = {"cmd.exe", "powershell.exe", "conhost.exe", "windowsterminal.exe"}

def current_time_str() -> str:
    return datetime.datetime.now(datetime.timezone.utc).astimezone().strftime("%Y-%m-%dT%H:%M:%S%z")

def main(argv: list[str]) -> int:
    argparser = argparse.ArgumentParser()
    argparser.add_argument("usersfile", nargs='?', type=str, help="file containing a newline-separated list of users to kill shells of")
    argparser.add_argument("--badips", help="file containing a newline-separated list of IP addresses to monitor")
    argparser.add_argument("--db", default="monitor-process.db", help="path to the database file to store information in. default is ./monitor-process.db")
    argparser.add_argument("--invert", action="store_true", help="invert the logic in the usersfile argument - kill the shells of all users except those specified in usersfile. not recommended unless you know what you're doing.")
    argparser.add_argument("--list", action="store_true", help="list all users running a process and exit")
    argparser.add_argument("--log", help="log to the specified file in addition to printing to console")
    argparser.add_argument("--mattermost", action="store_true", help="attempt to log in to mattermost")

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
    
    mattermost_token, mattermost_api, mattermost_channel = None, None, None
    if parsedarguments["mattermost"]:
        mattermost_token = mattermost.get_token()
        if mattermost_token is not None:
            mattermost_api = mattermost.MattermostApi(mattermost_token)
            mattermost_channel = mattermost_api.get_some_channel()

    def printlog(message: str):
        print(message)
        if parsedarguments["log"]:
            try:
                with open(parsedarguments["log"], "a") as logfile:
                    logfile.write(message + "\n")
            except PermissionError:
                print("WARNING: Failed to log to file \"" + parsedarguments["log"] + "\", got permission denied.")
        if mattermost_api and mattermost_channel:
            mattermost_api.post_message(mattermost_channel["id"], message)

    bad_ips = []
    try:
        if parsedarguments["badips"]:
            with open(parsedarguments["badips"], 'r') as badipsfile:
                bad_ips.append(badipsfile.readline().strip())
    except FileNotFoundError:
        print("ERROR: File \"" + parsedarguments["badips"] + "\" not found.")
        return 1
    except PermissionError:
        print("ERROR: Got permission denied when opening \"" + parsedarguments["badips"] + "\"")
        return 1
    no_shell_users = []
    try:
        if parsedarguments["usersfile"]:
            with open(parsedarguments["usersfile"], 'r') as usersfile:
                no_shell_users.append(usersfile.readline().strip())
    except FileNotFoundError:
        print("ERROR: File \"" + parsedarguments["usersfile"] + "\" not found, try --help for help")
        return 1
    except PermissionError:
        print("ERROR: Got permission denied when opening file \"" + parsedarguments["usersfile"] + "\"")
        return 1
    while True:
        initialize_db = False  # Whether we need to initialize the database
        if not pathlib.Path(parsedarguments["db"]).exists():
            initialize_db = True
        database = sqlite3.connect(parsedarguments["db"])
        if initialize_db:
            database.execute("CREATE TABLE \"processes\" ( \"pid\" INTEGER NOT NULL UNIQUE, \"executable\" TEXT, \"user\" TEXT, \"files\" TEXT, \"inetconns\" TEXT, \"subprocesses\" TEXT, PRIMARY KEY(\"pid\") )")
            database.execute("CREATE TABLE \"badprocesses\" ( \"pid\" INTEGER NOT NULL UNIQUE, \"nextwarntime\" INTEGER, PRIMARY KEY(\"pid\"));")
            database.commit()

        saved_pids = []
        for row in database.execute("SELECT pid,executable FROM processes"):
            saved_pids.append((row[0], row[1]))
        
        # Delete PIDs of processes not in the process list
        for pid, executable in saved_pids:
            if not psutil.pid_exists(pid):
                print("Process " + executable + " with PID " + str(pid) + " has terminated")
                database.execute("DELETE FROM processes WHERE pid=?", (pid,))
                database.execute("DELETE FROM badprocesses WHERE pid=?", (pid,))
                database.commit()
        
        # Check processes with unwanted connections
        for row in database.execute("SELECT pid, nextwarntime FROM badprocesses"):
            try:
                still_flagged = False  # Whether we should keep this entry in the database
                process = psutil.Process(pid=row[0])
                connections_list = []
                for connection in process.connections():
                    connection_type = "unknown"
                    if connection.type == socket.SOCK_STREAM:   
                        connection_type = "tcp"
                    elif connection.type == socket.SOCK_DGRAM:
                        connection_type = "udp"
                    connections_list.append(connection.raddr.ip + ":" + str(connection.raddr.port) + "/" + connection_type)
                    if connection.raddr.ip in bad_ips:
                        still_flagged = True
                if time.time() > row[1]:
                    printlog(process.exe() + " running as " + process.username() + " (" + str(process.pid) + ") established the following connections, some of which were flagged: " + ", ".join(connections_list))
                    # Warn again 5 minutes later
                    database.execute("UPDATE badprocesses SET nextwarntime=? WHERE pid=?", (int(time.time() + 300), row[0]))
                    database.commit()
                if not still_flagged:
                    database.execute("DELETE FROM badprocesses WHERE pid=?", (row[0],))
                    database.commit()
            except psutil.NoSuchProcess:
                # Process no longer exists
                database.execute("DELETE FROM badprocesses WHERE pid=?", (row[0],))
                pass
        for process in psutil.process_iter():
            try:
                # Check Internet connections
                unwanted_connection = False
                for connection in process.connections():
                    if connection.raddr:
                        if connection.raddr.ip in bad_ips:
                            unwanted_connection = True
                badprocesses_pids = []  # The PIDs already in the database for badprocesses
                for row in database.execute("SELECT pid FROM badprocesses"):
                    badprocesses_pids.append(row[0])
                if unwanted_connection and process.pid not in badprocesses_pids:
                    database.execute("INSERT INTO badprocesses (pid, nextwarntime) VALUES (?,?)", (process.pid, int(time.time())))
                    database.commit()
                executable_name = pathlib.Path(process.exe()).name
                open_files = []
                for file in process.open_files():
                    open_files.append(file.path)
                connections = []
                for connection in process.connections():
                    if connection.type and connection.raddr:
                        connection_type = "unknown"
                        if connection.type == socket.SOCK_STREAM:
                            connection_type = "tcp"
                        elif connection.type == socket.SOCK_DGRAM:
                            connection_type = "udp"
                        connections.append(connection.raddr.ip + ":" + str(connection.raddr.port) + "/" + str(connection_type))
                if (os.name == "nt" and executable_name.lower() in shells_win) or \
                        (os.name != "nt" and executable_name in shells_nix):
                    process_in_database = False
                    for row in database.execute("SELECT 1 FROM processes WHERE pid=?", (process.pid,)):
                        process_in_database = True
                        break
                    if not process_in_database:
                        # New process
                        database.execute("INSERT INTO processes (pid, executable, user, files, inetconns, subprocesses) VALUES (?, ?, ?, ?, ?, ?)", 
                                         (process.pid, process.exe(), process.username(), json.dumps(open_files), json.dumps(connections), json.dumps([c.pid for c in process.children(True)]), ))
                        printlog(process.username() + " started process " + process.exe() + " with pid " + str(process.pid))

                    saved_open_files = None
                    saved_connections = None
                    saved_child_pids = None
                    for row in database.execute("SELECT files,inetconns,subprocesses FROM processes WHERE pid=?", (process.pid,)):
                        saved_open_files = json.loads(row[0])
                        saved_connections  = json.loads(row[1])
                        saved_child_pids = json.loads(row[2])
                        break
                    if saved_child_pids is not None and set((c.pid for c in process.children(True))) - set(saved_child_pids):
                        string_to_log = "Process " + str(process.pid) + " (running " + str(process.exe()) + " as user " + process.username() + ") started the following subprocesses: "
                        for c in process.children(True):
                            if c.pid not in saved_child_pids:
                                string_to_log += c.exe() + " (" + str(c.pid) + "), "
                        printlog(string_to_log)
                    
                    # Update the database
                    database.execute("UPDATE processes SET files=?, inetconns=?, subprocesses=? WHERE pid=?;", 
                                     (json.dumps(open_files), json.dumps(connections), json.dumps([c.pid for c in process.children(True)]), process.pid))
                    database.commit()

                    # Kill shells
                    if (not parsedarguments["invert"] and process.username() in no_shell_users) or \
                            (parsedarguments["invert"] and process.username() not in no_shell_users):
                        # Don't kill shells for root user
                        if process.username().lower() != "root":
                            printlog("Killed process " + str(process.pid))
                            process.kill()
            except psutil.AccessDenied:
                # We aren't root/administrator. Life goes on...
                pass
        database.close()
        time.sleep(3)
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv))
