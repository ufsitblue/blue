import argparse
import configparser
import csv
import pathlib
import random
import sys
import typing

import plankaapi

def main(argv: list[str]) -> int:
    argparser: argparse.ArgumentParser =  argparse.ArgumentParser("Sets up the Planka server")
    argparser.add_argument("services_csv", type=pathlib.Path,
            help="The input CSV file containing service info")
    parsedargs: dict[str, typing.Any] = vars(argparser.parse_args(argv[1:]))

    config: configparser.ConfigParser = configparser.ConfigParser()
    config.read("plankaconfig.ini")
    planka: plankaapi.PlankaApi = plankaapi.PlankaApi(config["planka.connection"]["baseurl"], 
            config["planka.connection"]["username"], config["planka.connection"]["password"])
    
    # Figure out the users that need to be added
    users_to_add: set[str] = set()
    for username in config["login"]["users"].split(','):
        users_to_add.add(username.strip())
    for planka_user in planka.get_users():
        users_to_add.discard(planka_user.username)

    for username in users_to_add:
        planka.create_user(username, "ChangeMe123!", username + "@email.invalid")
    
    ccdc_project: typing.Optional[plankaapi.PlankaProject] = None
    for planka_project in planka.get_projects():
        if planka_project.name == "CCDC":
            ccdc_project = planka_project
            break
    if ccdc_project is None:
        ccdc_project = planka.create_project("CCDC")

    ccdc_board: typing.Optional[plankaapi.PlankaBoard] = None
    for planka_board in ccdc_project.get_boards():
        if planka_board.name == "CCDC":
            ccdc_board = planka_board
            break
    if ccdc_board is None:
        ccdc_board = ccdc_project.create_board("CCDC", 5)
        ccdc_board.create_label("Urgent", 20)
        ccdc_board.create_label("In progress", 40)
        ccdc_board.create_label("Done", 60)
    
    # Add all users as editors.
    user_ids_to_add: set[str] = {planka_user.user_id for planka_user in planka.get_users()}
    existing_user_ids: set[str] ={board_membership.user_id for board_membership in ccdc_board.get_users()}
    for user_id in user_ids_to_add - existing_user_ids:
        ccdc_board.add_user(user_id, "editor")

    # Now, ccdc_board contains a Planka board object.
    list_position: int = 100
    """The position we are currently on for the current list."""
    ccdc_board.create_list("TODO", list_position)
    list_position += 100

    # TODO Create all the lists for scored services
    with open(parsedargs["services_csv"], 'r') as services_csv_file:
        services_csv_reader: csv.DictReader = csv.DictReader(services_csv_file)
        for service in services_csv_reader:
            list_name: str = service["ip"] + ("" if service["hostname"].strip() == "" 
                    else " (" + service["hostname"] + ")")
            
            planka_list: typing.Optional[plankaapi.PlankaList] = None
            for board_list in ccdc_board.get_lists():
                # Try to find the list with the same name.
                if board_list.name == list_name:
                    planka_list = board_list
            if planka_list is None:
                planka_list = ccdc_board.create_list(list_name, list_position)
                list_position += 100
                planka_list.create_card("Blackout", 50)
                planka_list.create_card("Change passwords", 100)
                planka_list.create_card("Allow firewall traffic", 150)
                planka_list.create_card("Check network connections", 200)
                planka_list.create_card("Back up service configs", 250)
                planka_list.create_card("General Hardening (Windows/Linux)", 300)

            planka_list.create_card("Harden port " + service["port"] + " (" + service["service"] + ")", random.randint(1000, 5000))


    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv))
