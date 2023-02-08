"""Define the adapter of the Auth store."""
import os
import shutil
from contextlib import suppress
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, List, Optional, Tuple

from goodconf import GoodConf
from pydantic import BaseModel, EmailStr, Field  # noqa: E0611
import logging
from ruyaml import YAML

from ..exceptions import NotFoundError, TooManyError
from .key import GPGKey

Name = Annotated[str, Field(regex="^[0-9a-zA-Z_ ]+$")]
Username = Name

log = logging.getLogger(__name__)

class Group(BaseModel):
    """Model a group of users."""

    name: Name
    users: List[Username] = Field(default_factory=list)

    def add_users(self, users: List['User']) -> None:
        """Add a list of users from the group."""
        self.users = list(set(self.users + [user.name for user in users]))

    def remove_users(self, users: List['User']) -> None:
        """Remove a list of users from the group."""
        for user in users:
            try:
                self.users.remove(user.name)
            except ValueError:
                log.info(f'User {user.name} is not part of the {self.name} group')


class User(BaseModel):
    """Model a user of the password store."""

    name: Username
    email: EmailStr
    key: GPGKey


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

    def check_auth_file(self, store_dir: Path) -> str:
        """Return the AuthStore configuration file.

        If the file doesn't exist it will copy the default template.
        """
        auth_file = (store_dir / ".auth.yaml").expanduser()

        if not auth_file.exists():
            shutil.copyfile("assets/auth.yaml", auth_file)

        return auth_file

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
        users = users or []
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
        user_match = [
            user
            for user in self.users
            if identifier in (user.name, user.key, user.email)
        ]

        if len(user_match) == 0:
            raise NotFoundError(f"There is no user that matches {identifier}.")
        if len(user_match) == 1:
            return user_match[0]
        raise TooManyError(
            f"More than one user matched the selected criteria {identifier}."
        )

    def find_keys(self, identifier: str) -> List["GPGKey"]:
        """Return the gpg keys that matches the identifier.

        Args:
            identifier: string that identifies a user or group. It can be either the
                name, the email or the gpg key.
        """
        users = []

        # Find in the users
        with suppress(NotFoundError):
            users.append(self.get_user(identifier))

        # Find in the groups
        with suppress(NotFoundError):
            users.extend(
                [self.get_user(user) for user in self.get_group(identifier).users]
            )

        return [user.key for user in users]

    def change_group_users(self, group_name: str, add_identifiers: Optional[List[str]] = None, remove_identifiers: Optional[List[str]] = None
    ) -> Tuple[List["GPGKey"], List["GPGKey"]]:
        """Change the list of users of an existent group.

        Args:
            group_name: Group to change
            add_identifiers: Unique identifier of a user to add. It can be the user name, email or gpg key.
            remove_identifiers: Unique identifier of a user to remove. It can be the user name, email or gpg key.

        Returns:
            List of new GPG keys to authorize.
            List of existent GPG keys to remove.
        """
        add_identifiers = add_identifiers or []
        remove_identifiers = remove_identifiers or []
        group = self.get_group(group_name)
        
        # Add users
        new_users = [self.get_user(id_) for id_ in add_identifiers]
        group.add_users(users=new_users)

        # Remove users
        users_to_remove = [self.get_user(id_) for id_ in remove_identifiers]
        group.remove_users(users=users_to_remove)

        self.save()

        return (
            [user.key for user in new_users],
            [user.key for user in users_to_remove],
        )
