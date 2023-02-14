"""Define the adapter of the Auth store."""

import logging
import os
import shutil
from contextlib import suppress
from pathlib import Path
from typing import Annotated, Dict, List, Optional

from goodconf import GoodConf
from pydantic import BaseModel, EmailStr, Field  # noqa: E0611
from ruyaml import YAML

from ..exceptions import NotFoundError, TooManyError
from .key import GPGKey

Name = Annotated[str, Field(regex="^[0-9a-zA-Z_ ]+$")]
Username = Name
Identifier = Name
GPGIDPath = str


log = logging.getLogger(__name__)


class Group(BaseModel):
    """Model a group of users."""

    name: Name
    users: List[Username] = Field(default_factory=list)

    def add_users(self, users: List["User"]) -> None:
        """Add a list of users from the group."""
        for user in users:
            log.info(f"Adding user {user.name} to group {self.name}")
        self.users = list(set(self.users + [user.name for user in users]))

    def remove_users(self, users: List["User"]) -> None:
        """Remove a list of users from the group."""
        for user in users:
            log.info(f"Removing user {user.name} from group {self.name}")
            try:
                self.users.remove(user.name)
            except ValueError:
                log.info(f"User {user.name} is not part of the {self.name} group")


class User(BaseModel):
    """Model a user of the password store."""

    name: Username
    email: EmailStr
    key: GPGKey


class AuthStore(GoodConf):
    """Define the adapter of the authorisation store."""

    groups: List[Group]
    users: List[User]
    access: Dict[GPGIDPath, List[Identifier]] = Field(default_factory=dict)

    class Config:
        """Define the default files to check."""

        default_files = [
            ".auth.yaml",
            os.path.expanduser("~/.password-store/.auth.yaml"),
        ]

    @staticmethod
    def check_auth_file(store_dir: Path) -> Path:
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
        return str(self._config_file)

    def reload(self) -> None:
        """Reload the contents of the authentication store."""
        self.load(self.config_file)

    def load(self, filename: Optional[str] = None) -> None:
        """Load a configuration file."""
        self._config_file = filename
        super().load(filename)

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

    def get_user(self, identifier: Identifier) -> User:
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

    def find_keys(self, identifier: Identifier) -> List["GPGKey"]:
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

    def change_group_users(
        self,
        group_name: str,
        add_identifiers: Optional[List[Identifier]] = None,
        remove_identifiers: Optional[List[Identifier]] = None,
    ) -> None:
        """Change the list of users of an existent group.

        Args:
            group_name: Group to change
            add_identifiers: Unique identifier of a user to add. It can be the
                user name, email or gpg key.
            remove_identifiers: Unique identifier of a user to remove. It can
                be the user name, email or gpg key.
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

    def authorize(
        self,
        gpg_id: GPGIDPath,
        identifier: Identifier,
    ) -> None:
        """Authorize a group or person to a directory of the password store.

        It will tweak the `.gpg-id` file to specify the desired access and it
        will reencrypt the files of that directory.

        Args:
            pass_dir_path: internal path of a directory of the password store.
                Not a real Path
            identifier: Unique identifier of a group or person.
                It can be the group name, person name, email or gpg key. Can be
                used in addition to `keys`.

        Raises:
            ValueError: When trying to authorize a file.
                If we authorize a file with keys different than the ones
                specified on the .gpg-id file, the next time someone reencrypts
                the file using `pass` directly, the change will be overwritten.
                We could handle this case, but not for the MVP.

        """
        try:
            access = self.access[gpg_id]
        except KeyError:
            access = []

        # new users
        with suppress(NotFoundError, TooManyError):
            user = self.get_user(identifier)
            new_access = user.name
            if new_access not in access:
                log.info(f'  Authorizing access to user {user.name}: {user.email} ({user.key})')
                access.append(new_access)

        # new groups
        with suppress(NotFoundError):
            group = self.get_group(identifier)
            if user:
                raise ValueError(
                    f'Both user {user.name} and group {group.name} matched identifier {identifier}, cancelling authorization.'
                )
            new_access = group.name
            if new_access not in access:
                log.info(f'  Authorizing access to group {group.name}')
                access.append(new_access)

        self.access[gpg_id] = access
        

    def allowed_keys(
        self,
        gpg_id: GPGIDPath,
    ) -> List[GPGKey]:
        """Return the allowed gpg keys of a gpg-id path.

        Args:
            path: A real path to an element of the pass store.

        Raises:
            NotFoundError: If there is no data of that gpg-id file.
        """
        try:
            authorees = self.access[gpg_id]
        except KeyError as error:
            raise NotFoundError(
                f"There is no access information for the gpg-id file {gpg_id}"
            )

        keys = []
        for authoree in authorees:
            keys.extend(self.find_keys(authoree))

        return keys
