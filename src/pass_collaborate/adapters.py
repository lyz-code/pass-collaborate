"""Define the adapters of the program."""

import logging
import os
from pathlib import Path
from typing import List, Optional

from goodconf import GoodConf
from pydantic import BaseModel  # noqa: E0611
from pydantic import EmailStr
from ruamel.yaml import YAML

from .exceptions import NotFoundError
from .model import Group, User

log = logging.getLogger(__name__)


class KeyStore(BaseModel):
    """Define the adapter of the `gpg` key store."""

    key_dir: Path


class PassStore(BaseModel):
    """Define the adapter of the `pass` password store.

    I've thought of using [passpy](https://github.com/bfrascher/passpy) but it doesn't
    look maintained anymore.
    """

    store_dir: Path
    key: KeyStore


class AuthStore(GoodConf):  # type: ignore
    """Define the adapter of the authorisation store."""

    groups: List[Group]
    users: List[User]

    class Config:
        """Define the default files to check."""

        default_files = [
            os.path.expanduser("~/.password-store/.auth.yaml"),
            ".auth.yaml",
        ]

    def add_user(self, name: str, key: str, email: Optional[str] = None) -> User:
        """Create a new user.

        Args:
            name: name of the user
            key: GPG key of the user.
            email: Email of the user.

        Raises:
            ValueError: if the user already exists
        """
        if name in self.user_names:
            raise ValueError(f"The user {name} already exists.")

        new_user = User(name=name, key=key, email=EmailStr(email))
        self.users.append(new_user)
        self.save()
        return new_user

    def add_group(self, name: str, users: Optional[List[str]] = None) -> Group:
        """Create a new group of users.

        Args:
            name: name of the group
            users: users to add to the group.

        Raises:
            ValueError: if the group already exists
        """
        if name in self.group_names:
            raise ValueError(f"The group {name} already exists.")

        new_group = Group(name=name, users=users)
        self.groups.append(new_group)
        self.save()
        return new_group

    @property
    def group_names(self) -> List[str]:
        """Return the names of the groups in the authentication store."""
        return [group.name for group in self.groups]

    @property
    def user_names(self) -> List[str]:
        """Return the names of the users in the authentication store."""
        return [user.name for user in self.users]

    @property
    def config_file(self) -> str:
        """Return the path to the config file."""
        # E1101: Class 'Config' has no '_config_file' member. But it does
        # W0212: Accessing an internal attribute of an external library. I know...
        return self.Config._config_file  # type: ignore # noqa: E1101, W0212

    def reload(self) -> None:
        """Reload the contents of the authentication store."""
        self.load(self.config_file)

    def save(self) -> None:
        """Save the contents of the authentication store."""
        with open(self.config_file, "w+", encoding="utf-8") as file_cursor:
            yaml = YAML()
            yaml.default_flow_style = False
            yaml.dump(self.dict(), file_cursor)

    def get_group(self, name: str) -> Group:
        """Return the group that matches the group name."""
        try:
            return [group for group in self.groups if group.name == name][0]
        except IndexError as error:
            raise NotFoundError(f"The group {name} doesn't exist.") from error

    def get_user(self, identifier: str) -> User:
        """Return the user that matches the user identifier.

        Args:
            identifier: string that identifies the user. It can be either the name,
                the email or the gpg key.
        """
        try:
            return [group for group in self.groups if group.name == name][0]
        except IndexError as error:
            raise NotFoundError(f"The group {name} doesn't exist.") from error

    def add_users_to_group(self, name: str, users: List[str]) -> None:
        """Add a list of users to an existent group."""
        group = self.get_group(name)
        if group.users is None:
            group.users = []

        group.users = list(set(group.users + users))
        self.save()
