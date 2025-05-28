"""
An implementation of the Planka API.

All requests are made using the Python `requests` module. Note that exceptions
thrown by the `requests` module may be thrown by methods in this module. See also
https://docs.python-requests.org/en/latest/api/#exceptions

## Prerequisites
 - Python 3.9+
 - Python `requests` module. If not installed, install it with 
   `pip install requests`.

## Architecture
Here is a high-level overview of concepts in Planka
```
PlankaApi -> PlankaProject -> PlankaBoard -> PlankaList -> PlankaCard -> PlankaComment
PlankaApi -> PlankaUser
```
where `->` means "contains"

## Examples
```
>>> import plankaapi
>>> api = plankaapi.PlankaApi("http://localhost:3000", "username", "password")
>>> project = api.create_project("My awesome project")
```

## License
```
Copyright (C) 2025  Yuliang Huang <https://gitlab.com/yhuang885>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, version 3.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
```
"""
from __future__ import annotations

import datetime
import random
import typing

import requests

LABEL_COLORS: tuple[str, ...] = ("berry-red", "pumpkin-orange", "lagoon-blue", 
        "pink-tulip", "light-mud", "orange-peel", "bright-moss", 
        "antique-blue", "dark-granite", "lagune-blue", "sunny-grass", 
        "morning-sky", "light-orange", "midnight-blue", "tank-green", 
        "gun-metal", "wet-moss", "red-burgundy", "light-concrete", 
        "apricot-red", "desert-sand", "navy-blue", "egg-yellow", 
        "coral-green", "light-cocoa")
"""All valid colors for labels"""

# TODO Add sensible __repr__() and __eq__() functions to all classes that lack them.

class AuthenticationError(RuntimeError):
    """
    Raised when there was an issue authenticating with the Planka server.
    """
    pass

class PlankaObjectNotFoundError(FileNotFoundError):
    """
    Raised when a Planka object was not found.
    
    Applies to projects, boards, lists, cards, comments, and users.
    """
    pass

class PlankaApi:
    """
    Represents the Planka API
    
    All requests are made using the python Requests library
    """
    
    def __init__(self, base_url: str, username: str, password: str, timeout: float = 30.0) -> None:
        """
        :param base_url: The base URL of the Planka API. Do not include a trailing slash.
        :param username: The email or username of the account to authenticate with
        :param password: The password of the account to authenticate with.
        :param timeout: An optional timeout value in seconds for requests made to the server. 
        Defaults to 30.
        
        :raises AuthenticationError: If the provided username and password are invalid.
        """
        self.__base_url: str = base_url
        self.__timeout: float = timeout
        
        # Get an access token from /access-tokens
        access_token_response: requests.Response = requests.post(self.__base_url + "/access-tokens", json={
            "emailOrUsername": username,
            "password": password,
        }, timeout=self.__timeout)
        
        # Check to see if the credentials provided were correct.
        if access_token_response.status_code == 401:
            raise AuthenticationError("Invalid username or password.")
        access_token_response.raise_for_status()
        
        # Save the authentication token
        self.__auth_token: str = access_token_response.json()["item"]
        
        # Initialize the requests session that we will use
        self.__requests_session: requests.Session = requests.Session()
        self.__requests_session.headers["Authorization"] = "Bearer " + self.__auth_token
    
    @property
    def auth_token(self) -> str:
        """
        The authentication token fetched from the server.
        """
        return self.__auth_token
    
    @property
    def base_url(self) -> str:
        """
        The base URL of the Planka API
        """
        return self.__base_url
    
    @property
    def requests_session(self) -> requests.Session:
        """
        A mostly-internal object to get the request session, used to make
        requests to the Planka server.
        
        This allows for TCP connection reuse, saving bandwidth. See also
        https://docs.python-requests.org/en/latest/user/advanced/#session-objects
        
        Should generally not be called by code outside of plankaapi.py, 
        unless you *really* know what you're doing.
        
        This property does not support being set.
        """
        return self.__requests_session
    
    @property
    def timeout(self) -> float:
        """
        An optional timeout value in seconds for requests made to the server.
        
        This property supports being set.
        """
        return self.__timeout
    @timeout.setter
    def timeout(self, value: float) -> None:
        """
        An optional timeout value in seconds for requests made to the server.
        
        This property supports being set.
        """
        if value < 0.0:
            raise ValueError("The request timeout must be greater than or equal to 0, not " + 
                    str(value))
        self.__timeout = value
    
    def create_project(self, name: str) -> PlankaProject:
        """
        Createa a project within this Planka instance
        
        :param name: The name of the project to create
        
        :return: The PlankaProject instance that was just created.
        :raises AuthenticationError: If the token is invalid
        """
        response: requests.Response = self.__requests_session.post(self.__base_url + "/projects", 
                json={"name": name}, timeout=self.__timeout)
        response.raise_for_status()  # TODO Replace with proper error handling
        
        # Extract the ID of the newly created project and return the corresponding PlankaProject object.
        return PlankaProject(self, response.json()["item"]["id"])
    
    def create_user(self, username: str, password: str, email: str, name: typing.Optional[str] = None) -> PlankaUser:
        """
        Creates a user within this Planka instance
        
        :param username: The username that the new user can use to sign in
        :param password: A password for the new user
        :param email: An email for the new user.
        :param name: An optional first and last name for the new user. If omitted,
        will default to the username
        """
        if name is None:
            name = username
        
        response: requests.Response = self.__requests_session.post(self.__base_url + "/users", 
                json={"email": email, "name": name, "password": password, "username": username},
                timeout=self.__timeout)
        response.raise_for_status()  # TODO Replace with proper error handling
        
        # Extract the ID of the newly created user and return the corresponding PlankaUser instance.
        return PlankaUser(self, response.json()["item"]["id"])
    
    def get_projects(self) -> list[PlankaProject]:
        """
        Gets the projects that are a part of this Planka instance
        
        :return: A (possibly-empty) list of PlankaProject instances
        :raises AuthenticationError: If the token is invalid
        """
        response: requests.Response = self.__requests_session.get(self.__base_url + "/projects", timeout=self.__timeout)
        response.raise_for_status()  # TODO Replace with proper error handling
        
        # Extract all the project IDs and return them.
        planka_projects: list[PlankaProject] = []
        for planka_project in response.json()["items"]:
            planka_projects.append(PlankaProject(self, planka_project["id"]))
        return planka_projects
    
    def get_users(self) -> list[PlankaUser]:
        """
        Gets the users that are a part of this Planka instance
        
        :return: A list of PlankaUser instances
        """
        response: requests.Response = self.__requests_session.get(self.__base_url + "/users", timeout=self.__timeout)
        response.raise_for_status()  # TODO Replace with proper error handling
        
        # Extract all the user IDs and return them in a list
        planka_users: list[PlankaUser] = []
        for planka_user in response.json()["items"]:
            planka_users.append(PlankaUser(self, planka_user["id"]))
        return planka_users
    
    def __eq__(self, other) -> bool:
        return self.base_url == other.base_url and self.auth_token == other.auth_token
    
    def __repr__(self) -> str:
        return "<PlankaApi object at " + self.__base_url + ">"


class PlankaProject:
    """
    Represents a project, the highest level of organization in Planka.
    
    Projects exist within a specific Planka instance, represented by a `PlankaApi`
    object.
    """
    def __init__(self, planka_api: PlankaApi, project_id: str) -> None:
        """
        :param planka_api: The PlankaApi instance that the project exists in.
        :param project_id: The ID of the project.
        
        :raises AuthenticationError: If the token in planka_api is invalid
        :raises PlankaObjectNotFoundError: If an invalid ID is passed in
        """
        self.__planka_api: PlankaApi = planka_api
        self.__project_id: str = project_id
        
        # Request information about this project from the API
        project_response: requests.Response = self.__planka_api.requests_session.get(self.__planka_api.base_url + 
                "/projects/" + self.__project_id, timeout=self.__planka_api.timeout)
        if project_response.status_code == 401:
            raise AuthenticationError("Invalid access token in planka_api instance")
        elif project_response.status_code == 404:
            raise PlankaObjectNotFoundError("Project with ID \"" + self.__project_id + "\" not found")
        project_response.raise_for_status()
        project_response_json: dict = project_response.json()

        self.__name: str = project_response_json["item"]["name"]
        
        # Add all the boards to a special __board_ids variable
        self.__board_ids: list[str] = []
        # Only add boards if they're there.
        if "boards" in project_response_json["included"]:
            for planka_board in project_response_json["included"]["boards"]:
                self.__board_ids.append(planka_board["id"])
    
    @property
    def name(self) -> str:
        """
        The name (title) of this project.
        """
        return self.__name
    
    @property
    def planka_api(self) -> PlankaApi:
        """
        The PlankaApi instance this board is associated with
        """
        return self.__planka_api
    
    @property
    def project_id(self) -> str:
        """
        The ID of the project within the PlankaApi instance.
        """
        return self.__project_id
    
    def create_board(self, name: str, position: int) -> PlankaBoard:
        """
        Create a board within this project.
        
        :param name: The name of the board.
        :param position: The position to create the board in. Used to order the boards.
        
        :return: The PlankaBoard instance.
        """
        create_board_response: requests.Response = self.__planka_api.requests_session.post(
                self.__planka_api.base_url + "/projects/" + self.__project_id + "/boards", 
                json={"name": name, "position": position},
                timeout=self.__planka_api.timeout)
        create_board_response.raise_for_status()  # TODO Replace with real error-handling code
        return PlankaBoard(self.__planka_api, create_board_response.json()["item"]["id"])
    
    def delete(self) -> None:
        """
        Deletes this project. This object should no longer be used after a successful
        call to `delete()`. Any subsequent usage of a deleted instance will result 
        in undefined behavior.
        """
        delete_project_response: requests.Response = self.__planka_api.requests_session.delete(
                self.__planka_api.base_url + "/projects/" + self.__project_id, timeout=self.__planka_api.timeout)
        delete_project_response.raise_for_status()  # TODO Replace with real error-handling code
    
    def get_boards(self) -> list[PlankaBoard]:
        """
        Gets the boards within this project.
        
        :return: A (possibly-empty) list of PlankaBoard instances
        """
        planka_boards: list[PlankaBoard] = []
        for board_id in self.__board_ids:
            planka_boards.append(PlankaBoard(self.__planka_api, board_id))
        return planka_boards
    
    def __eq__(self, other) -> bool:
        return self.planka_api == other.planka_api and self.project_id == other.project_id
    
    def __repr__(self) -> str:
        return "<PlankaProject " + str(self.__project_id) + ", titled " + str(self.__name) + ">"


class PlankaBoard:
    """
    Represents a board in a specific Planka instance.
    
    A `PlankaBoard` object exists in the context of a `PlankaProject` object.
    """
    def __init__(self, planka_api: PlankaApi, board_id: str) -> None:
        """
        :param planka_api: The PlankaApi instance that the board exists in.
        :param board_id: The ID of this board.
        
        :raises AuthenticationError: If the token in planka_api is invalid
        :raises PlankaObjectNotFoundError: If an invalid ID is passed in
        """
        self.__planka_api: PlankaApi = planka_api
        self.__board_id: str = board_id
        
        # Get the response and parse the JSON
        board_response: requests.Response = self.__planka_api.requests_session.get(self.__planka_api.base_url + 
                "/boards/" + self.__board_id, timeout=self.__planka_api.timeout)
        if board_response.status_code == 401:
            raise AuthenticationError("Invalid access token in planka_api instance")
        elif board_response.status_code == 404:
            raise PlankaObjectNotFoundError("Board with ID \"" + self.__board_id + "\" not found")
        board_response.raise_for_status()
        board_response_json: dict = board_response.json()

        # Extract the name and position
        self.__name: str = board_response_json["item"]["name"]
        self.__position: int = board_response_json["item"]["position"]
    
    @property
    def board_id(self) -> str:
        """
        The ID of this board
        """
        return self.__board_id
    
    @property
    def name(self) -> str:
        """
        The name of this board
        """
        return self.__name
    
    @property
    def planka_api(self) -> PlankaApi:
        """
        The PlankaApi instance this board is associated with
        """
        return self.__planka_api
    
    @property
    def position(self) -> int:
        """
        The position of this board. Lower numbers are positioned 
        before higher numbers.
        """
        return self.__position
    
    def add_user(self, user_id: str, role: str) -> PlankaBoardMembership:
        """
        Adds a user to this board

        :param user_id: The ID of the user to ad
        :param role: The role of the user to add. Use "editor" to indicate edit privileges.
        """
        add_user_response: requests.Response = self.__planka_api.requests_session.post(
                self.__planka_api.base_url + "/boards/" + self.__board_id + "/memberships",
                json={"userId": user_id, "role": role},
                timeout=self.__planka_api.timeout)
        add_user_response.raise_for_status()  # TODO Add proper error-handling

        add_user_response_json = add_user_response.json()

        # Return a new PlankaBoardMembership instance with relevant information filled in
        return PlankaBoardMembership(self.__planka_api, add_user_response_json["item"]["id"],
                self.__board_id, user_id, role)

    def create_label(self, name: str, position: int, color: typing.Optional[str] = None) -> None:
        """
        Creates a label within the board.

        At this time, there is no way to modify or delete labels after they are created.

        :param name: The name of the label to be created.
        :param position: The position of the label to be created.
        :param color: Optionally, the color of the label to be created. If specified, must be
        a value from LABEL_COLORS

        :raises ValueError: If the string passed in for parameter `color` is invalid.
        """
        if color is None:
            color = random.choice(LABEL_COLORS)
        if color not in LABEL_COLORS:
            raise ValueError("Unknown color \"" + str(color) + 
                    "\", must be one of the colors in LABEL_COLORS")
        create_label_response: requests.Response = self.__planka_api.requests_session.post(
                self.__planka_api.base_url + "/boards/" + self.__board_id + "/labels",
                json={"name": name, "color": color, "position": position},
                timeout=self.__planka_api.timeout)
        create_label_response.raise_for_status()  # TODO Add proper error-handling

    def create_list(self, name: str, position: int) -> PlankaList:
        """
        Creates a list within this board.
        
        :param name: The name of the list to be created.
        :param position: The position of the list to be created.
        Lower numbers will be put before higher numbers.
        
        :return: The newly created `PlankaList` instance
        """
        create_list_response: requests.Response = self.__planka_api.requests_session.post(
                self.__planka_api.base_url + "/boards/" + self.__board_id + "/lists", 
                json={"name": name, "position": position},
                timeout=self.__planka_api.timeout)
        create_list_response.raise_for_status()  # TODO Add real error-handling code
        return PlankaList(self.__planka_api, self.__board_id, create_list_response.json()["item"]["id"],
                name, position, [], datetime.datetime.now().astimezone(datetime.timezone.utc), None)
    
    def delete(self) -> None:
        """
        Delete this board. No calls to methods of `PlankaBoard` should be made
        after a call to `PlankaBoard.delete()`
        """
        delete_board_response: requests.Response = self.__planka_api.requests_session.delete(
                self.__planka_api.base_url + "/boards/" + self.__board_id, timeout=self.__planka_api.timeout)
        delete_board_response.raise_for_status()  # TODO Add proper error-handling
    
    def get_lists(self) -> list[PlankaList]:
        """
        Gets the lists that are part of this board.
        
        :return: A Python list of `PlankaList` objects associated with this board.
        """
        # Get the response and parse the JSON
        board_response: requests.Response = self.__planka_api.requests_session.get(self.__planka_api.base_url + 
                "/boards/" + self.__board_id, timeout=self.__planka_api.timeout)
        if board_response.status_code == 401:
            raise AuthenticationError("Invalid access token in planka_api instance")
        elif board_response.status_code == 404:
            raise PlankaObjectNotFoundError("Board with ID \"" + self.__board_id + "\" not found")
        board_response.raise_for_status()
        board_response_json: dict = board_response.json()
        
        # Extract all IDs of lists and cards contained in this board.
        card_ids: dict[str, list[str]] = {}
        """A dict mapping list_id -> [card_id, card_id, ...]"""
        self.__planka_lists: list[PlankaList] = []
        for planka_card in board_response_json["included"]["cards"]:
            try:
                card_ids[planka_card["listId"]].append(planka_card["id"])
            except KeyError:
                card_ids[planka_card["listId"]] = [planka_card["id"]]
        
        for planka_list in board_response_json["included"]["lists"]:
            planka_list_id: str = planka_list["id"]
            
            # Parse the creation and last updated datetimes
            create_time: datetime.datetime = datetime.datetime.strptime(planka_list["createdAt"], "%Y-%m-%dT%H:%M:%S.%fZ")
            create_time = create_time.replace(tzinfo=datetime.timezone.utc)
            update_time: typing.Optional[datetime.datetime] = None
            if planka_list["updatedAt"] is not None:
                update_time = datetime.datetime.strptime(planka_list["updatedAt"], "%Y-%m-%dT%H:%M:%S.%fZ")
                update_time = update_time.replace(tzinfo=datetime.timezone.utc)
            
            card_ids_in_this_list: list[str] = []
            """A list of IDs of cards that belong to the current PlankaList object"""
            try:
                # Pass the corresponding list by reference for speed.
                # Note: Do NOT modify card_ids_in_this_list in this function after this point.
                # These lists can be modified after this function returns.
                card_ids_in_this_list = card_ids[planka_list_id]
            except KeyError:
                # No cards in this list
                pass
            
            # Add the PlankaList to the list.
            self.__planka_lists.append(PlankaList(self.__planka_api, self.__board_id, planka_list_id, 
                    planka_list["name"], planka_list["position"], card_ids_in_this_list, 
                    create_time, update_time))
        
        return self.__planka_lists

    def get_users(self) -> list[PlankaBoardMembership]:
        """
        Gets the users associated with this board, as `PlankaBoardMembership` objects

        :return: A list of `PlankaBoardMembership` objects.
        """
        # Get the response and parse the JSON
        board_response: requests.Response = self.__planka_api.requests_session.get(self.__planka_api.base_url + 
                "/boards/" + self.__board_id, timeout=self.__planka_api.timeout)
        if board_response.status_code == 401:
            raise AuthenticationError("Invalid access token in planka_api instance")
        elif board_response.status_code == 404:
            raise PlankaObjectNotFoundError("Board with ID \"" + self.__board_id + "\" not found")
        board_response.raise_for_status()
        board_response_json: dict = board_response.json()

        # Extract all IDs of users within this board
        board_users: list[PlankaBoardMembership] = []
        for planka_board_membership_json in board_response_json["included"]["boardMemberships"]:
            board_users.append(PlankaBoardMembership(self.__planka_api, planka_board_membership_json["id"],
                    planka_board_membership_json["boardId"], planka_board_membership_json["userId"],
                    planka_board_membership_json["role"]))

        return board_users


class PlankaBoardMembership:
    """
    Represents a membership relation between a board and a user.

    This is a simple "bucket" of information and should not be initialized
    directly. Instead, use `PlankaBoard.add_user()` and 
    `PlankaBoard.get_users()`.
    """

    def __init__(self, planka_api: PlankaApi, membership_id: str, 
                 board_id: str, user_id: str, role: str) -> None:
        """
        :param planka_api: The PlankaApi instance that this board membership
        relation belongs to.
        :param membership_id: The ID of the board membership relation
        :param board_id: The ID of board that the user belongs to.
        :param user_id: The ID of the user that belongs to the board
        :param role: The role of the user.
        """
        self.__planka_api: PlankaApi = planka_api
        self.__membership_id: str = membership_id
        self.__board_id: str = board_id
        self.__user_id: str = user_id
        self.__role: str = role
    
    @property
    def board_id(self) -> str:
        """
        The ID of the board that the user belongs to.
        """
        return self.__board_id

    @property
    def membership_id(self) -> str:
        """
        The ID of this board membership relation
        """
        return self.__membership_id
    
    @property
    def planka_api(self) -> PlankaApi:
        """
        The PlankaApi instance that this board membership
        relation belongs to.
        """
        return self.__planka_api

    @property
    def role(self) -> str:
        """
        The role of the user within the board
        """
        return self.__role

    @property
    def user_id(self) -> str:
        """
        THe ID of the user that belongs to the board.
        """
        return self.__user_id

    def delete(self) -> None:
        """
        Delete this board membership relation. This instance should
        no longer be used after a successful call to `delete()`. Doing 
        so anyways will result in undefined behavior
        """
        delete_board_membership_response: requests.Response = self.__planka_api.requests_session.delete(
                self.__planka_api.base_url + "/board-memberships/" + self.__membership_id,
                timeout=self.__planka_api.timeout)
        delete_board_membership_response.raise_for_status()  # TODO Add proper error-handling


class PlankaList:
    """
    Represents a list in a specific Planka instance.
    
    Unlike boards, cards, and comments, this is a dumb object. `PlankaList` objects
    should only be directly initialized through `PlankaBoard.create_list()` and
    `Plankaboard.get_lists()`.
    
    A `PlankaList` exists within a `PlankaBoard`.
    """
    def __init__(self, planka_api: PlankaApi, board_id: str, list_id: str, 
            name: str, position: int, card_ids: list[str], create_time: datetime.datetime, 
            update_time: typing.Optional[datetime.datetime]) -> None:
        """
        The parameter `card_ids`, unlike all other parameters, intentionally 
        does not have a corresponding getter. Use `get_cards()` instead.
        
        :param planka_api: The PlankaApi instance that this list exists in.
        :param board_id: The ID of the board that this list is a part of
        :param list_id: The ID of this list.
        :param name: The name of this list.
        :param position: The position of this list.
        :param card_ids: The IDs of the cards associated with this list.
        :param create_time: The creation time of this list.
        :param update_time: The time of last update of this list.
        
        :raises AuthenticationError: If the token in planka_api is invalid
        :raises PlankaObjectNotFoundError: If an invalid ID is passed in
        """
        self.__planka_api: PlankaApi = planka_api
        self.__board_id: str = board_id
        self.__list_id: str = list_id
        self.__name: str = name
        self.__position: int = position
        self.__card_ids: list[str] = card_ids
        self.__create_time: datetime.datetime = create_time
        self.__update_time: typing.Optional[datetime.datetime] = update_time
    
    @property
    def board_id(self) -> str:
        """
        The ID of the board that this list is a part of
        """
        return self.__board_id
    
    @property
    def create_time(self) -> datetime.datetime:
        """
        The creation time of this list
        """
        return self.__create_time
    
    @property
    def list_id(self) -> str:
        """
        The ID of this list
        """
        return self.__list_id
    
    @property
    def name(self) -> str:
        """
        The name of this list.
        """
        return self.__name
    
    @property
    def planka_api(self) -> PlankaApi:
        """
        The PlankaApi instance this board is associated with
        """
        return self.__planka_api
    
    @property
    def position(self) -> int:
        """
        The position of this list
        """
        return self.__position
    
    @property
    def update_time(self) -> typing.Optional[datetime.datetime]:
        """
        The time of last update of this list. Will be None if the
        list was never updated after creation.
        """
        return self.__update_time
    
    def create_card(self, name: str, position: int) -> PlankaCard:
        """
        Creates a card within this list.
        
        :param name: The name of the card to create
        :param position: The position to create the card at relative to other cards. Lower
        numbers will be placed before higher numbers.
        
        :return: A `PlankaCard` instance representing the card that was just created
        :raises AuthenticationError: If the session token is invalid.
        """
        create_card_response: requests.Response = self.__planka_api.requests_session.post(
                self.__planka_api.base_url + "/lists/" + self.__list_id + "/cards",
                json={"name": name, "position": position},
                timeout=self.__planka_api.timeout)
        if create_card_response.status_code == 401:
            raise AuthenticationError("Invalid access token in planka_api instance")
        create_card_response.raise_for_status()
        return PlankaCard(self.__planka_api, create_card_response.json()["item"]["id"])
    
    def delete(self) -> None:
        """
        Delete this list. This object should no longer be used if this method is called and succeeds.
        """
        delete_list_response: requests.Response = self.__planka_api.requests_session.delete(
                self.__planka_api.base_url + "/lists/" + self.__list_id, timeout=self.__planka_api.timeout)
        if delete_list_response.status_code == 401:
            raise AuthenticationError("Invalid access token in planka_api instance")
        if delete_list_response.status_code == 404:
            raise PlankaObjectNotFoundError("List with ID \"" + self.__list_id + "\" not found.")
        delete_list_response.raise_for_status()
    
    def get_cards(self) -> list[PlankaCard]:
        """
        Gets the cards that are part of this list
        """
        planka_cards: list[PlankaCard] = []
        for card_id in self.__card_ids:
            planka_cards.append(PlankaCard(self.__planka_api, card_id))
        return planka_cards


class PlankaCard:
    """
    Represents a card in a specific Planka instance
    """
    def __init__(self, planka_api: PlankaApi, card_id: str) -> None:
        """
        :param planka_api: The PlankaApi instance that this card exists in.
        :param card_id: The ID of this card.
        """
        self.__planka_api: PlankaApi = planka_api
        self.__card_id: str = card_id
        
        # Get the response and parse the JSON
        card_response: requests.Response = self.__planka_api.requests_session.get(self.__planka_api.base_url + 
                "/cards/" + self.__card_id, timeout=self.__planka_api.timeout)
        if card_response.status_code == 401:
            raise AuthenticationError("Invalid access token in planka_api instance")
        elif card_response.status_code == 404:
            raise PlankaObjectNotFoundError("Card with ID \"" + self.__card_id + "\" not found")
        card_response.raise_for_status()
        card_response_json = card_response.json()
        
        # Get the name and position of the card from the JSON
        self.__name: str = card_response_json["item"]["name"]
        self.__position: int = card_response_json["item"]["position"]
    
    @property
    def card_id(self) -> str:
        """
        The ID of this card.
        """
        return self.__card_id
    
    @property
    def name(self) -> str:
        """
        The name of this card
        """
        return self.__name
    
    @property
    def planka_api(self) -> PlankaApi:
        """
        The PlankaApi instance this card is associated with
        """
        return self.__planka_api
    
    @property
    def position(self) -> int:
        """
        The position of this card. Lower numbers go before
        higher numbers.
        """
        return self.__position
    
    def create_comment(self, text: str) -> PlankaComment:
        """
        Add a comment to this card
        
        :param text: The text of the comment to add to the card.
        
        :return: A `PlankaComment` instance representing the comment that was just created.
        """
        # Send the request and parse the response JSON
        create_comment_response: requests.Response = self.__planka_api.requests_session.post(
                self.__planka_api.base_url + "/cards/" + self.__card_id + "/comment-actions", 
                json={"text": text},
                timeout=self.__planka_api.timeout)
        create_comment_response.raise_for_status()  # TODO Add proper error-handling
        create_comment_response_json = create_comment_response.json()
        
        # Return a new PlankaComment instance with relevant information filled in.
        return PlankaComment(self.__planka_api, create_comment_response_json["item"]["id"],
                create_comment_response_json["item"]["data"]["text"], 
                datetime.datetime.now().astimezone(datetime.timezone.utc), None)
    
    def delete(self) -> None:
        """
        Delete this card. No other methods of `PlankaCard` should be called after a call to
        `PlankaCard.delete()`
        """
        delete_card_response: requests.Response = self.__planka_api.requests_session.delete(
                self.__planka_api.base_url + "/cards/" + self.__card_id, 
                timeout=self.__planka_api.timeout)
        delete_card_response.raise_for_status()  # TODO Add proper error-handling
    
    def get_comments(self) -> list[PlankaComment]:
        """
        Gets the comments associated with this card
        
        :return: A list of comments associated with this card
        """
        card_action_response: requests.Response = self.__planka_api.requests_session.get(
                self.__planka_api.base_url + "/cards/" + self.__card_id + "/actions", 
                timeout=self.__planka_api.timeout)
        card_action_response.raise_for_status()  # TODO Add real error-handling
        card_action_response_json = card_action_response.json()
        
        planka_comments: list[PlankaComment] = []
        """A list of comments to return"""
        for card_action in card_action_response_json["items"]:
            if card_action["type"] == "commentCard":
                # This is a comment.
                # Parse the dates associated with this comment
                create_time: datetime.datetime = datetime.datetime.strptime(card_action["createdAt"], "%Y-%m-%dT%H:%M:%S.%fZ")
                create_time = create_time.replace(tzinfo=datetime.timezone.utc)
                update_time: typing.Optional[datetime.datetime] = None
                if card_action["updatedAt"] is not None:
                    update_time = datetime.datetime.strptime(card_action["updatedAt"], "%Y-%m-%dT%H:%M:%S.%fZ")
                    update_time = update_time.replace(tzinfo=datetime.timezone.utc)
                
                # Add the comment to the list of comments to return.
                planka_comments.append(PlankaComment(self.__planka_api, card_action["id"],
                        card_action["data"]["text"], create_time, update_time))
        return planka_comments


class PlankaComment:
    """
    Represents a comment in a card in a specific Planka instance.
    
    `PlankaComment` objects are contained in `PlankaCard` objects. Unlike `PlankaCard` instances,
    `PlankaComment` instances are simple "buckets" of information. This class should not be directly
    instantiated. Instead, use `PlankaCard.create_comment()` and `PlankaCard.get_comments()` to get
    `PlankaComment` instances.
    """
    def __init__(self, planka_api: PlankaApi, comment_id: str, text: str, 
            create_time: datetime.datetime, update_time: typing.Optional[datetime.datetime]) -> None:
        """
        :param planka_api: The PlankaApi instance that this comment exists in.
        :param comment_id: The ID of this comment
        :param text: The text (body) of this comment
        :param create_time: The time of creation of the comment
        :param update_time: The time at which the comment was last updated
        """
        self.__planka_api: PlankaApi = planka_api
        self.__comment_id = comment_id
        self.__text: str = text
        self.__create_time: datetime.datetime = create_time
        self.__update_time: typing.Optional[datetime.datetime] = update_time
    
    @property
    def comment_id(self) -> str:
        """
        The ID of this comment
        """
        return self.__comment_id
    
    @property
    def create_time(self) -> datetime.datetime:
        """
        The time of creation of the comment
        """
        return self.__create_time
    
    @property
    def text(self) -> str:
        """
        The text (body) of this comment
        """
        return self.__text
    
    @property
    def update_time(self) -> typing.Optional[datetime.datetime]:
        """
        The time at which the comment was last updated
        """
        return self.__update_time
    
    @property
    def planka_api(self) -> PlankaApi:
        """
        The PlankaApi instance this board is associated with
        """
        return self.__planka_api
    
    def delete(self) -> None:
        """
        Delete this comment. The `PlankaComment` instance should no longer
        be used after a call to `delete()`. Calling any other methods will 
        result in undefined behavior after `delete()` succeeds.
        """
        delete_comment_response: requests.Response = self.__planka_api.requests_session.delete(
                self.__planka_api.base_url + "/comment-actions/" + self.__comment_id,
                timeout=self.__planka_api.timeout)
        delete_comment_response.raise_for_status()  # TODO Add proper error-handling


class PlankaUser:
    """
    Represents a user of a Planka instance
    """
    def __init__(self, planka_api: PlankaApi, user_id: str) -> None:
        """
        :param planka_api: The PlankaApi instance that this user exists in.
        :param user_id: The ID of this user (not the same as the username or email).
        """
        self.__planka_api: PlankaApi = planka_api
        self.__user_id: str = user_id
        
        # Make the request and parse the resulting JSON
        user_response: requests.Response = self.__planka_api.requests_session.get(self.__planka_api.base_url + 
                "/users/" + self.__user_id, timeout=self.__planka_api.timeout)
        if user_response.status_code == 401:
            raise AuthenticationError("Invalid access token in planka_api instance")
        elif user_response.status_code == 404:
            raise PlankaObjectNotFoundError("User with ID \"" + self.__user_id + "\" not found")
        user_response_json = user_response.json()
        
        self.__email: str = user_response_json["item"]["email"]
        self.__name: typing.Optional[str] = user_response_json["item"]["name"]
        self.__username: str = user_response_json["item"]["username"]
    
    def email(self) -> str:
        """
        The email of the user. Can be used to log in.
        """
        return self.__email
    
    def name(self) -> typing.Optional[str]:
        """
        The (first and last) name of the user. Not to be confused 
        with the username.
        """
        return self.__name
    
    @property
    def planka_api(self) -> PlankaApi:
        """
        The PlankaApi instance this user is associated with
        """
        return self.__planka_api
    
    @property
    def user_id(self) -> str:
        """
        The ID of this user (not the same as the username or email).
        """
        return self.__user_id
    
    @property
    def username(self) -> str:
        """
        The username that can be used at the sign-in screen.
        """
        return self.__username
    
    def delete(self) -> None:
        """
        Delete this user. This `PlankaUser` instance should not be used after
        `PlankaUser.delete()` is called
        """
        delete_user_response: requests.Response = self.__planka_api.requests_session.delete(
                self.__planka_api.base_url + "/users/" + self.__user_id,
                timeout=self.__planka_api.timeout)
        delete_user_response.raise_for_status()  # TODO Add proper error-handling
    
    def __eq__(self, other) -> bool:
        return self.planka_api == other.planka_api and self.user_id == other.user_id
    
    def __repr__(self) -> str:
        return "<PlankaUser " + self.__user_id + ", username " + self.__username + \
                ", email " + self.__email + ">"


if __name__ == "__main__":
    print("Starting unit tests for plankaapi.py...")
    print("WARNING: This may delete any work you have saved. Do not test on any " + 
            "Planka instance with data you actually care about.")
    planka_base_url: str = input("Please enter the base url for the Planka API: ").strip()
    planka_username: str = input("Please enter your username: ")
    planka_password: str = input("Please enter your password: ")
    
    import time
    
    print("Connecting to API...")
    api: PlankaApi = PlankaApi(planka_base_url, planka_username, planka_password, timeout=20.0)
    print("Testing user creation...")
    created_user: PlankaUser = api.create_user("testuser01", "ChangeMe123!", "testuser01@email.test", "Test User 1")
    print("Testing project creation...")
    created_project: PlankaProject = api.create_project("Project-" + str(int(time.time())))
    print("Created project \"" + created_project.name + "\".")
    print("Testing board creation...")
    created_board: PlankaBoard = created_project.create_board("Test board", 120)
    print("Created board \"" + created_board.name + "\" at position " + str(created_board.position))
    print("Testing label creation...")
    created_board.create_label("Test label", 100)
    print("Adding user to board...")
    created_board_membership: PlankaBoardMembership = created_board.add_user(created_user.user_id, "editor")
    print("Added user " + created_board_membership.user_id + " to board " + created_board_membership.board_id)
    print("Testing list creation...")
    created_list: PlankaList = created_board.create_list("Test list", 120)
    print("Created list \"" + created_list.name + "\" at position " + str(created_list.position))
    print("Testing card creation...")
    created_card: PlankaCard = created_list.create_card("Test card", 120)
    print("Created card \"" + created_card.name + "\" at position " + str(created_card.position))
    print("Testing comment creation...")
    created_comment: PlankaComment = created_card.create_comment("Test comment")
    print("Created comment \"" + created_comment.text + "\"")
    
    print("Querying users...")
    print(api.get_users())
    print("Querying projects...")
    print(api.get_projects())
    print("Querying boards...")
    print(PlankaProject(api, created_project.project_id).get_boards())
    print("Querying lists...")
    print(created_board.get_lists())
    print("Querying cards...")
    print(created_board.get_lists()[0].get_cards())
    print("Querying comments...")
    print(created_card.get_comments())
    
    print("Deleting comment...")
    created_comment.delete()
    del created_comment
    print("Deleting card...")
    created_card.delete()
    del created_card
    print("Deleting list...")
    created_list.delete()
    del created_list
    print("Deleting board...")
    created_board.delete()
    del created_board
    print("Deleting project...")
    created_project.delete()
    del created_project
    print("Deleting user...")
    created_user.delete()
    del created_user
    
    print("Testing non-existent board...")
    try:
        random_board: PlankaBoard = PlankaBoard(api, "34324321472")
        print("Did not get any error, which is probably not the correct behavior.")
    except PlankaObjectNotFoundError as e:
        print("Got the expected error: " + str(e))
    
    print("All tests complete.")
