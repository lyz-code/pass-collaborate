"""Define the adapters of the program."""

import logging
import os
from contextlib import suppress
from pathlib import Path
from typing import Generator, List, Optional

from gnupg import GPG
from goodconf import GoodConf
from pydantic import BaseModel  # noqa: E0611
from pydantic import EmailStr
from ruamel.yaml import YAML

from .exceptions import DecryptionError, NotFoundError, TooManyError
from .model import GPGKey, Group, User

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

        Raises:
            NotFoundError: if file doesn't exist
            DecryptError: can't decrypt file
        """
        try:
            result = self.gpg.decrypt_file(str(path))
        except ValueError as error:
            raise NotFoundError(
                f"Could not find the file to decrypt in {path}"
            ) from error

        if result.returncode != 0:
            # E1101: Instance of 'Crypt' has no 'stderr' member. But it does
            raise DecryptionError(result.stderr)  # noqa: E1101

        return str(result)

    def can_decrypt(self, path: Path) -> bool:
        """Test if the user can decrypt a file.

        Args:
            path: Path to the file to decrypt.
        """
        try:
            self.decrypt(path)
        except (NotFoundError, DecryptionError):
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

    class Config:
        """Configure the pydantic model."""

        arbitrary_types_allowed = True

    def path(
        self, pass_path: Optional[str] = None, is_dir: Optional[bool] = None
    ) -> Path:
        """Return the path to the file or directory of the password internal path.

        Args:
            pass_path: internal path of the password store. Not a real Path

        Raises:
            ValueError: if is_dir is true and the result path is not a directory.

        Example:
        >>> self.path('web')
        Path('~/.password-store/web')

        >>> self.path()
        Path('~/.password-store')

        >>> self.path('bastion')
        Path('~/.password-store/bastion.gpg')
        """
        if pass_path is None:
            return self.store_dir

        path = Path(self.store_dir / pass_path)

        if is_dir and not path.is_dir():
            raise ValueError(f"{path} is not a directory when it was expected to be")

        if not path.exists() and path.suffix == "":
            path = path.with_name(f"{path.name}.gpg")
            if not path.exists():
                raise NotFoundError(
                    f"Could not find the element {pass_path} in the password store"
                )

        return path

    def _gpg_id_file(self, path: Path) -> Path:
        """Return the first .gpg-id file that applies to a pass path.

        Args:
            path: A real path to an element of the pass store.
        """
        gpg_id_path = path / ".gpg-id"

        if gpg_id_path.is_file():
            return gpg_id_path

        if path == self.store_dir:
            raise NotFoundError("Couldn't find the root .gpg-id of your store")

        return self._gpg_id_file(path.parent)

    def allowed_keys(
        self, path: Optional[Path] = None, new_keys: Optional[List[str]] = None
    ) -> List[str]:
        """Return the allowed gpg keys of the path.

        * For files it analyzes the gpg data.
        * For directories it traverses the paths to find the first .gpgid file,
            returning it's content.

        Args:
            path: A real path to an element of the pass store.
            new_keys: List of keys to add to the allowed_keys
        """
        path = path or self.store_dir
        new_keys = new_keys or []
        existent_keys = self._gpg_id_file(path).read_text().splitlines()

        return existent_keys + new_keys

    def authorize(self, id_: str, pass_dir_path: str) -> None:
        """Authorize a group or person to a directory of the password store.

        Args:
            id_: Unique identifier of a group or person. It can be the group name,
                person name, email or gpg key.
            pass_dir_path: internal path of a directory of the password store.
                Not a real Path

        Raises:
            ValueError: When trying to authorize a file.
                If we authorize a file with keys different than the ones specified on
                the .gpg-id file, the next time someone reencrypts the file using `pass`
                directly, the change will be overwritten. We could handle this case, but
                not for the MVP.
        """
        if self.path(pass_dir_path).is_file():
            raise ValueError(
                "Authorizing access to a file is not yet supported, "
                "please use the parent directory."
            )

        new_key = self.key.get_key(id_)

        for path in self._pass_paths(pass_dir_path):
            log.info(f"Authorizing {id_} to access password {self._pass_path(path)}")
            self.key.encrypt(path, self._allowed_keys(path=path, new_keys=[new_key]))

    def _pass_paths(self, pass_dir_path: str) -> Generator[Path, None, None]:
        """Return all the password files of a pass directory.

        Args:
            pass_dir_path: internal path of a directory of the password store.
                Not a real Path
        """
        return self.path(pass_dir_path, is_dir=True).rglob("*.gpg")

    def _pass_path(self, path: Path) -> str:
        """Return the pass representation of a real path.

        It's the reverse of self.path

        Args:
            path: Path to a real directory or file.
        """
        pass_path = str(path).replace(f"{self.store_dir}", "").replace("/", "")

        if path.is_file():
            pass_path = pass_path.replace(".gpg", "")

        return pass_path


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

    def get_keys(self, identifier: str) -> List[GPGKey]:
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

    def add_users_to_group(self, name: str, users: List[str]) -> None:
        """Add a list of users to an existent group."""
        group = self.get_group(name)
        if group.users is None:
            group.users = []

        group.users = list(set(group.users + users))
        self.save()
