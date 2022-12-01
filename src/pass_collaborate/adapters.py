"""Define the adapters of the program."""

import logging
import os
from pathlib import Path
from typing import Generator, List, Optional

from gnupg import GPG
from goodconf import GoodConf
from pydantic import BaseModel  # noqa: E0611
from pydantic import EmailStr
from ruamel.yaml import YAML

from .exceptions import NotFoundError, TooManyError
from .model import Group, User

log = logging.getLogger(__name__)


class KeyStore:
    """Define the adapter of the `gpg` key store."""

    def __init__(self, key_dir: Path) -> None:
        """Set the gpg connector.

        Raises:
            NotFoundError: If the directory doesn't exist
        """
        if not key_dir.is_dir():
            raise NotFoundError(f"{key_dir} is not a directory that holds gnupg data.")
        self.key_dir = key_dir
        self.gpg = GPG(gnupghome=key_dir)

    def __repr__(self) -> str:
        """Return a string that represents the object."""
        return f"KeyStore(key_dir={self.key_dir})"

    def decrypt(self, path: Path) -> str:
        """Decrypt the contents of a file.

        Args:
            path: Path to the file to decrypt.
        """
        result = self.gpg.decrypt(str(path))

        # E1101: Instance of 'Crypt' has no 'stderr' member. But it does
        if "no valid OpenPGP data found" in result.stderr:  # noqa: E1101
            raise NotFoundError(
                f"No valid data found in {path}.",
            )

        return result

    def can_decrypt(self, path: Path) -> bool:
        """Test if the user can decrypt a file.

        Args:
            path: Path to the file to decrypt.

        Raises:
            FileNotFoundError: if file doesn't exist
        """
        try:
            self.decrypt(path)
        except NotFoundError:
            return False
        return True

    @property
    def private_key_fingerprints(self) -> List[str]:
        """Return the IDs of the private keys."""
        return [key["fingerprint"] for key in self.gpg.list_keys(True)]


class PassStore(BaseModel):
    """Define the adapter of the `pass` password store.

    I've thought of using [passpy](https://github.com/bfrascher/passpy) but it doesn't
    look maintained anymore.
    """

    store_dir: Path
    key: KeyStore

    class Config:
        """Configure the pydantic model."""

        arbitrary_types_allowed = True

    def has_access(self, pass_path: str) -> bool:
        """Test if the user has access to the pass path.

        * For files it tries to decrypt it.
        * For directories it checks if our key is in the allowed keys of the .gpgid
            file.

        Args:
            pass_path: internal path of the password store. Not a real Path
        """
        path = self.path(pass_path)
        if path.is_dir():
            return self.key_id in self.allowed_keys(pass_path)

        return self.key.can_decrypt(path)

    def path(self, pass_path: Optional[str] = None) -> Path:
        """Return the path to the file or directory of the password internal path.

        Args:
            pass_path: internal path of the password store. Not a real Path

        Example:
        >>> self.path('web')
        Path('~/.password-store/web')

        >>> self.path()
        Path('~/.password-store')
        """
        if pass_path is None:
            return self.store_dir
        return Path(self.store_dir / pass_path)

    @property
    def key_id(self) -> str:
        """Return the gpg key id used by the password store user.

        Compare the private keys stored in the keys store with the keys used in the
        password storage.
        """
        keystore_keys = self.key.private_key_fingerprints
        matching_keys = list(set(keystore_keys) & set(self.allowed_keys()))

        if len(matching_keys) == 1:
            return matching_keys[0]
        raise ValueError(
            "There were more or less than 1 available gpg keys that is used "
            f"in the repository. Matching keys are: {matching_keys}"
        )

    def gpg_id_files(
        self, pass_path: Optional[str] = None
    ) -> Generator[Path, None, None]:
        """Return the .gpg-id files of a pass path and it's children.

        Args:
            pass_path: internal path of the password store. Not a real Path
        """
        return self.path(pass_path).rglob(".gpg-id")

    def allowed_keys(self, pass_path: Optional[str] = None) -> List[str]:
        """Return the allowed gpg keys of the pass path.

        * For files it analyzes the gpg data.
        * For directories it traverses the paths to find the first .gpgid file,
            returning it's content.

        Args:
            pass_path: internal path of the password store. Not a real Path
        """
        allowed_keys = []

        for gpg_id in self.gpg_id_files(pass_path):
            allowed_keys.extend(gpg_id.read_text().splitlines())

        return allowed_keys


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
        user_match = [
            user
            for user in self.users
            if identifier in (user.name, user.key, user.email)
        ]
        if len(user_match) == 0:
            raise NotFoundError(f"There is no user that matches {identifier}.")
        return user_match[0]

        raise TooManyError(
            f"More than one user matched the selected criteria {identifier}."
        )

    def add_users_to_group(self, name: str, users: List[str]) -> None:
        """Add a list of users to an existent group."""
        group = self.get_group(name)
        if group.users is None:
            group.users = []

        group.users = list(set(group.users + users))
        self.save()
