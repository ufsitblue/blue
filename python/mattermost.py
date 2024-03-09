import json
import os
import requests
import requests.exceptions
import typing

def get_token() -> typing.Optional[str]:
    """
    Get the session token for MatterMost
    """
    hostname, username, password = None, None, None
    try:
        hostname = os.environ["MATTERMOST_URL"]
        username = os.environ["MATTERMOST_USERNAME"]
        password = os.environ["MATTERMOST_PASSWORD"]
    except KeyError:
        print("Please make sure the following environment variables are set: MATTERMOST_URL, MATTERMOST_USERNAME, MATTERMOST_PASSWORD")
    
    if hostname is None or username is None or password is None:
        return None

    try:
        request = requests.post(hostname + "/api/v4/users/login", data=json.dumps({"login_id": username, "password": password}))
    except requests.exceptions.SSLError:
        request = requests.post(hostname + "/api/v4/users/login", data=json.dumps({"login_id": username, "password": password}))
    if request.status_code == 401:
        raise PermissionError("401 Unauthorized: incorrect username or password?")

    return request.headers["Token"]

class MattermostApi:
    def __init__(self, token: str):
        self.base_url = os.environ["MATTERMOST_URL"]
        self.token = token
        self.default_headers = {"Authorization": "Bearer " + token}

    def get_teams(self):
        r = requests.get(self.base_url + "/api/v4/teams", headers=self.default_headers)
        return r.json()

    def get_channels(self, team_guid: str):
        r = requests.get(self.base_url + "/api/v4/teams/" + team_guid + "/channels", headers=self.default_headers)
        return r.json()
    
    def get_some_channel(self):
        """
        Get a channel to post in. Requires interactive mode.
        :return: List or dict with channel information. Use get_some_channel()["id"} to get channel ID.
        """
        i = 0
        teams = []
        print("Choose a team...")
        for team in self.get_teams():
            print("[" + str(i) + "] " + team["display_name"])
            i += 1
            teams.append(team)
        choice = None
        while choice is None:
            try:
                choice = int(input("Make a choice: ").strip())
                if choice < 0 or choice >= len(teams):
                    print("Please enter a number between 0 and " + str(len(teams)))
                    choice = None
            except ValueError:
                print("Please enter an integer")
                choice = None
        team_to_use = teams[choice]
        
        channels = []
        i = 0
        print("Choose a channel...")
        for channel in self.get_channels(team_to_use["id"]):
            channels.append(channel)
            print("[" + str(i) + "] " + channel["display_name"])
            i += 1
        choice = None
        while choice is None:
            try:
                choice = int(input("Make a choice: ").strip())
                if choice < 0 or choice >= len(channels):
                    print("Please enter a number between 0 and " + str(len(channels)))
                    choice = None
            except ValueError:
                print("Please enter an integer.")
                choice = None
        return channels[choice]

    def post_message(self, channel_id: str, message_str):
        r = requests.post(self.base_url + "/api/v4/posts", headers=self.default_headers, data=json.dumps({"channel_id": channel_id, "message": message_str}))
        if r.status_code == 201:
            return 0
        else:
            return 1


