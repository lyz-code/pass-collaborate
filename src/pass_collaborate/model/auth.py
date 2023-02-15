"""Define the adapter of the Auth store."""

import logging
import os
import shutil
from contextlib import suppress
from pathlib import Path
from typing import Annotated, Dict, List, Optional, Union

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
                self.users.remove(user.email)
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

    @property
    def store_dir(self) -> Path:
        """Return the path to the store directory."""
        return Path(self.config_file).parent

    def reload(self) -> None:
        """Reload the contents of the authentication store."""
        self.load(self.config_file)

    def load(self, filename: Optional[str] = None) -> None:
        """Load a configuration file."""
        super().load(filename)
        self._config_file = filename
        self._load_gpg_id_files()

    def _load_gpg_id_files(self) -> None:
        """Load the data of the gpg-id files that is not already in the access store."""
        for gpg_id in Path(self.config_file).parent.rglob(".gpg-id"):
            try:
               self.access[str(gpg_id)]
            except KeyError:
               self.access[str(gpg_id)] = gpg_id.read_text().splitlines()


    def save(self) -> None:
        """Save the contents of the authentication store."""
        with open(self.config_file, "w+", encoding="utf-8") as file_cursor:
            yaml = YAML()
            yaml.default_flow_style = False
            yaml.dump(self.dict(), file_cursor)

    def get_group(self, name: str) -> Group:
        """Return the group that matches the group name.

        Raises:
            NotFoundError: if no group matches the identifier
        """
        group_match = [group for group in self.groups if group.name == name]

        if len(group_match) == 0:
            raise NotFoundError(f"There is no group that matches {name}.")
        if len(group_match) == 1:
            return group_match[0]
        raise TooManyError(
            f"More than one group matched the selected criteria {name}."
        )

    def get_user(self, identifier: Identifier) -> User:
        """Return the user that matches the user identifier.

        Args:
            identifier: string that identifies the user. It can be either the name,
                the email or the gpg key.

        Raises:
            NotFoundError: if no user matches the identifier
            TooManyError: if more than one user matches the identifier
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

    def get_identifier(self, identifier: Identifier) -> Union[Group, User]:
        """Return the group or user that matches the identifier."""
        # users
        user = None
        with suppress(NotFoundError, TooManyError):
            user = self.get_user(identifier)

        # new groups
        with suppress(NotFoundError, TooManyError):
            group = self.get_group(identifier)
            if user:
                raise ValueError(
                    f"Both user {user.name} and group {group.name} matched identifier {identifier}, cancelling authorization."
                )
            return group
        if user:
            return user
        raise NotFoundError(
            f"No user or group (or more than one) matches identifier {identifier}"
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

    def change_access(
        self,
        gpg_id: GPGIDPath,
        add_identifiers: Optional[List[Identifier]] = None,
        remove_identifiers: Optional[List[Identifier]] = None,
    ) -> None:
        """Authorize or revoke a group or person to a directory of the password store.

        It will store the access information in the auth store.

        Args:
            pass_dir_path: internal path of a directory of the password store.
                Not a real Path
            add_identifiers: Unique identifiers of groups or people to authorize.
                It can be the group name, person name, email or gpg key. Can be
                used in addition to `keys`.
            remove_identifiers: Unique identifiers of groups or people to revoke.
                It can be the group name, person name, email or gpg key. Can be
                used in addition to `keys`.
        """
        add_identifiers = add_identifiers or []
        remove_identifiers = remove_identifiers or []

        try:
            access = self.access[gpg_id]
        except KeyError:
            # If the access doesn't exist it will take it's parent as a base
            access = self.access[str(self._gpg_id_file(Path(gpg_id).parent))].copy()

        # Authorize new access
        for identifier in add_identifiers:
            new_access = self.get_identifier(identifier)

            if isinstance(new_access, User):
                log.info(
                    f"  Authorizing access to user {new_access.name}: "
                    f"{new_access.email} ({new_access.key})"
                )
            else:
                log.info(f"  Authorizing access to group {new_access.name}")

            access.append(new_access.name)

        # Revoke existing access
        for identifier in remove_identifiers:
            revoke = self.get_identifier(identifier)

            if isinstance(revoke, User):
                log.info(
                    f"  Revoking access to user {revoke.name}: "
                    f"{revoke.email} ({revoke.key})"
                )
            else:
                log.info(f"  Revoking access to group {revoke.name}")

            # We may pass here when we remove the access of a user to a group, therefore the
            # access to the directory doesn't change as it's binded to the group
            with suppress(ValueError):
                access.remove(revoke.name)

        self.access[gpg_id] = access

        self.save()

    def has_access(
        self, path: Path, identifier: "Identifier"
    ) -> bool:
        """Check in the stored access if the identdifier is allowed to the gpg_id file.

        Args:
            path: A real path to an element of the pass store.
            identifier: user or group identifier
        """
        authoree = self.get_identifier(identifier)
        access = self.access[str(self._gpg_id_file(path))]

        if isinstance(authoree, Group):
            return authoree.name in access
        else:
            __import__('pdb').set_trace()
            for id_ in access:
                authorized = self.get_identifier(id_)
                if authorized == authoree:
                    return True
                if isinstance(authorized, Group):
                    for user_id in authorized.users:
                        if self.get_user(user_id) == authoree:
                            return True
            return False
        

    def allowed_keys(
        self,
        gpg_id: GPGIDPath,
    ) -> List[GPGKey]:
        """Return the allowed gpg keys of a gpg-id path.

        Args:
            gpg_id: path to a .gpg_id file

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
            if len(authoree) == 40:
                # authoree is a gpg_id key
                keys.append(authoree)
            else:
                keys.extend(self.find_keys(authoree))

        return keys

    def _gpg_id_file(self, path: Union[Path,str]) -> Path:
        """Return the first .gpg-id file that applies to a path.

        Args:
            path: A real path to an element of the pass store.
        """
        if isinstance(path, str):
            path = Path(path)

        if path.match('*.gpg-id'):
            return path

        gpg_id_path = path / ".gpg-id"

        if gpg_id_path.is_file():
            return gpg_id_path

        if path == self.store_dir:
            raise NotFoundError("Couldn't find the root .gpg-id of your store")

        return self._gpg_id_file(path.parent)
