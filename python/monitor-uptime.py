import argparse
import os
import re
import socket
import sqlite3
import subprocess
import sys
import time
sys.dont_write_bytecode = True

import mattermost
import requests
import requests.exceptions

SUPPORTED_PROTOCOLS = {"tcp", "http", "https", "icmp"}

def main(argv: list[str]) -> int:
    argparser = argparse.ArgumentParser(description="Run with no arguments to start the monitoring daemon.")
    argparser.add_argument("--delete", "-D", help="Remove a service by ID. Call with --list first to get the unique IDs.")
    argparser.add_argument("--add", "-A", help="Add a service to monitor to the database. Format is <PROTOCOL>://<HOST>[:PORT][/PATH]. " + 
                           "PROTOCOL can be tcp, icmp, http, or https.")
    argparser.add_argument("--response", "-R", help="Expected response. If response does NOT match this regex, the check will fail. Will be ignored unless protocol is \"http\" or \"https\". Must be used with --add.")
    argparser.add_argument("--list", "-l", "-L", action="store_true", help="List the hosts currently being monitored.")
    argparser.add_argument("--db-location", help="Location of the SQLite database to store information in. Defaults to ./monitor-uptime.db")
    argparser.add_argument("--timeout", help="Timeout in seconds after which the server will be considered down. Default is 5.")
    
    argsdict = vars(argparser.parse_args())
    
    request_timeout = 5
    try:
        if argsdict["timeout"]:
            request_timeout = int(argsdict["timeout"])
            if request_timeout < 0:
                raise ValueError("request timeout must be greater than 0")
    except ValueError:
        print("ERROR: Expected a non-negative integer for TIMEOUT, not \"" + argsdict["timeout"] + "\"") 
        return 1

    dbfilename = "monitor-uptime.db"
    if argsdict["db_location"]:
        dbfilename = argsdict["db_location"]
    
    database = sqlite3.connect(dbfilename)

    # Create the services table if it doesn't exist.
    table_exists = False
    for row in database.execute("SELECT name FROM sqlite_master where type='table' AND name='services'"):
        table_exists = True
    if not table_exists:
        database.execute("CREATE TABLE \"services\" (\"id\" INTEGER NOT NULL UNIQUE, \"protocol\" TEXT, \"hostname\" TEXT, \"port\" INTEGER, \"path\" TEXT, \"response\" TEXT, \"up\" INTEGER, PRIMARY KEY(\"id\" AUTOINCREMENT));")
        database.commit()

    if argsdict["list"]:
        print("All hosts currently being monitored:")
        empty_list = True
        for row in database.execute("SELECT id,protocol,hostname,port,path,up,response FROM services;"):
            empty_list = False
            print(str(row[0]) + "\t" + row[1] + "://" + row[2] + (":" + str(row[3]) if row[3] else "") + 
                  (row[4] if row[4] else "/") + " - " + ("UP" if row[5] else "DOWN") + 
                  (" (expected response r\"" + row[6] + "\")" if row[6] else ""))
        if empty_list:
            print("No hosts in the database")
        database.close()
        return 0
    
    if argsdict["delete"]:
        database.execute("DELETE FROM services WHERE id=?", (argsdict["delete"],))
        database.commit()
        database.close()
        print("Deleting service with ID " + argsdict["delete"] + "...")
        return 0
    elif argsdict["add"]:
        protocol, host, port, path, response = None, None, None, None, None
        if "://" not in argsdict["add"]:
            print("ERROR: Missing protocol specifier in \"" + argsdict["add"] + "\"")
            return 1
        try:
            protocol, hoststring = argsdict["add"].split("://")
            path = "/" + '/'.join(hoststring.split('/')[1:])
            hoststring = hoststring.split('/')[0]
            if ':' in hoststring:
                host = ':'.join(hoststring.split(':')[:-1])
                port = int(hoststring.split(':')[-1])
            else:
                host = hoststring
        except IndexError:
            print("ERROR: Invalid format in \"" + argsdict["add"] + "\"")
            return 1
        except ValueError:
            print("ERROR: Failed to parse port value in \"" + argsdict["add"] + "\"")
            return 1
        protocol = protocol.lower()
        if not protocol in SUPPORTED_PROTOCOLS:
            print("ERROR: Unsupported protocol \"" + protocol + "\", must be one of: " + ", ".join(sorted(SUPPORTED_PROTOCOLS)))
            return 1

        # Default ports for HTTP and HTTPS
        if port is None:
            if protocol == "http":
                port = 80
            elif protocol == "https":
                port = 443
            elif protocol in {"tcp", "udp"}:
                print("ERROR: Must specify a port for " + protocol.upper())
                return 1
        
        if os.name == "nt" and protocol == "icmp":
            print("WARNING: ICMP ping requires Administrator privileges on Windows.")

        if path.strip() == "":
            path = None
        
        if argsdict["response"]:
            response = argsdict["response"]

        # Default to not up (0 - False)
        database.execute("INSERT INTO services (protocol, hostname, port, path, up, response) VALUES (?, ?, ?, ?, ?, ?)", (protocol, host, port, path, 0, response))
        database.commit()
        database.close()
        print(protocol.upper() + " monitor for host " + host + " added.")
        return 0
    
    # Try to get a Mattermost token (it's okay if we don't have one)
    mattermost_token = None
    try:
        mattermost_token = mattermost.get_token()
    except PermissionError:
        print("Incorrect Mattermost username or password, check the environment variables MATTERMOST_USERNAME and MATTERMOST_PASSWORD")
    mattermostapi, mattermostchannel = None, None
    if mattermost_token is not None:
        mattermostapi = mattermost.MattermostApi(mattermost_token)
        mattermostchannel = mattermostapi.get_some_channel()

    last_big_update_time = time.time()  # When we last had a major update about service status
    while True:
        services_down = []
        for row in database.execute("SELECT id, protocol, hostname, port, path, up, response FROM services"):
            uniqueid, protocol, host, port, path, upbefore, responseregex = row
            servicestring = protocol + "://" + host + (":" + str(port) if port else "") + \
                    (path if path else "/")
            upbefore = bool(upbefore)
            upafter = False  # Whether we are up after the check
            if protocol in {"http", "https"}:
                try:
                    httprequest = requests.get(protocol + "://" + hostname + ":" + port + (path if path else "/"), timeout=request_timeout, verify=False)
                    if responseregex:
                        if re.search(responseregex, httprequest.text):
                            upafter = True
                        else:
                            upafter = False
                    else:
                        upafter = True
                except (requests.ConnectionError, requests.Timeout):
                    # Timed out or connection refused.
                    upafter = False
            elif protocol == "tcp":
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(request_timeout)
                try:
                    sock.connect((host, port))
                    upafter = True
                except (ConnectionRefusedError, TimeoutError):
                    upafter = False
            elif protocol == "icmp":
                error_code = 0
                if os.name == "nt":
                    try:
                        subprocess.run(("ping", "-n", "1", host), capture_output=True, check=True)
                    except subprocess.CalledProcessError:
                        error_code = 1
                else:
                    try:
                        subprocess.run(("ping", "-c", "1", host), capture_output=True, check=True)
                    except subprocess.CalledProcessError:
                        error_code = 1
                if error_code == 0:
                    upafter = True
                else:
                    upafter = False
            
            if upbefore != upafter:
                print_string = "Service " + servicestring + " changed state from " + \
                        ("UP" if upbefore else "DOWN") + " to " + ("UP \u2705" if upafter else "DOWN \u274c")
                print(print_string)
                try:
                    if mattermostchannel is not None:
                        mattermostapi.post_message(mattermostchannel["id"], print_string)
                except Exception as e:
                    print("Got exception when trying to post to Mattermost:\n" + str(e))
            if not upafter:
                services_down.append(servicestring)
            database.execute("UPDATE services SET up=? WHERE id=?", (upafter, uniqueid))
            database.commit()
        if time.time() - last_big_update_time > 20:
            last_big_update_time = time.time()
            if services_down:
                big_update_str = "Note that the following services are DOWN:\n"
                for service in services_down:
                    big_update_str += " - " + service + "\n"
                print(big_update_str)
                try:
                    if mattermostchannel is not None:
                        mattermostapi.post_message(mattermostchannel["id"], big_update_str)
                except Exception as e:
                    print("Got exception when trying to post to Mattermost:\n" + str(e))
        time.sleep(2)
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv))
