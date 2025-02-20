"""
Checks for default credentials on machines
"""

import argparse
import configparser
import csv
import pathlib
import random
import sys
import time
import typing

import fabric
import paramiko
import requests

import plankaapi

def main(argv: list[str]) -> int:
    argparser: argparse.ArgumentParser = argparse.ArgumentParser(description="Checks for default credentials on machines")
    argparser.add_argument("--delay-time", "-d", default=2.0, type=float,
            help="The minimum delay between requests. Defaults to 2.")
    argparser.add_argument("--endpoint", "-e", default=None, type=str,
            help="The HTTP endpoint to send warnings to")
    argparser.add_argument("--planka-api", "-p", action="store_true",
            help="Whether to read Planka information from a config file")
    argparser.add_argument("user_file", type=pathlib.Path,
            help="A file containing a newline-separated list of users")
    argparser.add_argument("password_file", type=pathlib.Path,
            help="A file containing a newline-separated list of passwords to try for the users")
    argparser.add_argument("service_file", type=pathlib.Path,
            help="A CSV file containing a list of services.")
    parsedargs: dict[str, typing.Any] = vars(argparser.parse_args())

    users: list[str] = []
    passwords: list[str] = []
    services: list[tuple[str,int]] = []

    planka_api: typing.Optional[plankaapi.PlankaApi] = None
    if parsedargs["planka_api"]:
        planka_config: configparser.ConfigParser = configparser.ConfigParser()
        planka_config.read("plankaconfig.ini")
        planka_api = plankaapi.PlankaApi(planka_config["planka.connection"]["baseurl"], 
                planka_config["planka.connection"]["username"], planka_config["planka.connection"]["password"])

    planka_list: typing.Optional[plankaapi.PlankaList] = None
    if planka_api is not None:
        planka_project: typing.Optional[plankaapi.PlankaProject] = None
        for planka_project_i in planka_api.get_projects():
            if planka_project_i.name == "CCDC":
                planka_project = planka_project_i
        if planka_project is not None:
            planka_board: typing.Optional[plankaapi.PlankaBoard] = None
            for planka_board_i in planka_project.get_boards():
                if planka_board_i.name == "CCDC":
                    planka_board = planka_board_i
            if planka_board is not None:
                for planka_list_i in planka_board.get_lists():
                    if planka_list_i.name == "TODO":
                        planka_list = planka_list_i

    with open(parsedargs["user_file"], 'r') as usersfile:
        for user in usersfile:
            users.append(user.rstrip())
    with open(parsedargs["password_file"], 'r') as passwordsfile:
        for password in passwordsfile:
            passwords.append(password.rstrip())
    with open(parsedargs["service_file"], 'r') as servicescsvfile:
        servicescsvreader: csv.DictReader = csv.DictReader(servicescsvfile)
        for servicerow in servicescsvreader:
            if servicerow["service"] == "SSH":
                services.append((servicerow["ip"], int(servicerow["port"])))
    
    if parsedargs["endpoint"] is None:
        print("Note: No webhook endpoint configured. Notifications will be local only.")

    while True:
        for password in passwords:
            for user in users:
                for ip_address, port in services:
                    next_request_start_time: float = time.time() + parsedargs["delay_time"]
                    """The time that the next request should start by"""
                    ssh_connection = fabric.Connection(host=ip_address, port=port, user=user, connect_kwargs={
                        "password": password,
                        "timeout": 5
                    })
                    try:
                        ssh_connection.run("id")
                        print("ERROR: Connection succeeded to " + ip_address + " port " + str(port) + " over SSH. THIS IS BAD!")
                        if parsedargs["endpoint"] is not None:
                            try:
                                requests.post(parsedargs["endpoint"], data="\U0001F6A8 Connection succeeded to " + ip_address + 
                                        " port " + str(port) + " over SSH with default credentials! \U0001F6A8", headers={
                                            "X-Title": "[CRIT] Default Credentials Detected",
                                            "X-Priority": "urgent",
                                            "X_Tags": "defaultcreds,critical",
                                        })
                            except requests.RequestException as e:
                                print("WARN: An exception occured when publishing webhook: " + str(e))
                        if planka_list is not None:
                            planka_list.create_card("DEFAULT PASSWORD DETECTED ON " + ip_address + " PORT " + str(port) + 
                                    " WITH USER " + user + " PASSWORD " + password, random.randint(1000, 9000))
                    except paramiko.ssh_exception.NoValidConnectionsError:
                        print("WARN: SSH connection refused " + ip_address + ":" + str(port))
                    except TimeoutError:
                        print("WARN: SSH connection timed out " + ip_address + ":" + str(port))
                    except paramiko.ssh_exception.AuthenticationException:
                        print("Authentication failure")
                    except Exception as e:
                        print("ERROR: Got unexpected exception: " + str(e))

                    # Wait until whenever we should send the next request.
                    time.sleep(max(0, next_request_start_time - time.time()))

    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv))
