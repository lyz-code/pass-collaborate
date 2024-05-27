"""Define the data models of the password store."""

import logging
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Union

from pydantic import BaseModel, root_validator  # noqa: E0611

from ..adapters import KeyStore
from ..exceptions import NotFoundError, TooManyError
from .auth import AuthStore
from .key import GPGKey

if TYPE_CHECKING:
    from .auth import Identifier


log = logging.getLogger(__name__)


class PassStore(BaseModel):
    """Define the adapter of the `pass` password store.

    I've thought of using [passpy](https://github.com/bfrascher/passpy) but it
    doesn't look maintained anymore.

    Args:
        store_dir: Directory where the `pass` password store data lives.
        key_dir: Directory where the `gnupg` data lives.
    """

    store_dir: Path
    key_dir: Path
    auth_dir: Path = Path("")
    # ignore: the keys are going to be set by the root validator
    key: KeyStore = None  # type: ignore
    auth: AuthStore = None  # type: ignore

    class Config:
        """Configure the pydantic model."""

        arbitrary_types_allowed = True

    @root_validator(pre=True)
    @classmethod
    def set_adapters(cls, values: Dict[str, Any]) -> Dict[str, Any]:
        """Set the adapters."""
        key = KeyStore(key_dir=values["key_dir"])

        auth = AuthStore()
        try:
            if values["auth_dir"]:
                auth_dir = values["store_dir"] / values["auth_dir"]
            else:
                auth_dir = values["store_dir"]
        except KeyError:
            auth_dir = values["store_dir"]
        auth.load(f"{auth_dir}/.auth.yaml")
        cls._load_missing_users_from_keystore(key, auth)
        auth.save()

        values["key"] = key
        values["auth"] = auth
        return values

    @classmethod
    def _load_missing_users_from_keystore(
        cls, keystore: KeyStore, auth: AuthStore
    ) -> None:
        """Load the missing user information from the keystore."""
        missing_keys = []
        for key in cls.all_keys(auth.store_dir):
            try:
                auth.get_user(key)
            except NotFoundError:
                for stored_key in keystore.public_key_fingerprints:
                    if stored_key.match(key):
                        auth.add_user(
                            name=stored_key.name,
                            key=key,
                            email=stored_key.email,
                        )
                        break
                else:
                    missing_keys.append(key)
                log.error(f"Could not find key {key} in your keystore")

        if len(missing_keys) > 0:
            raise NotFoundError(
                "Please import the next gpg keys in your gpg keystore:\n"
                + "\n".join(missing_keys)
            )
        auth.save()

    def path(
        self, pass_path: Optional[str] = None, is_dir: Optional[bool] = None
    ) -> Path:
        """Return the path to the file or directory of the password internal path.

        Args:
            pass_path: internal path of the password store. Not a real Path.
            is_dir: if we expect `pass_path` to be a directory.

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

        if not path.exists():
            path = path.with_name(f"{path.name}.gpg")
            if not path.exists():
                raise NotFoundError(
                    f"Could not find the element {pass_path} in the password store"
                )

        return path

    def allowed_keys(
        self, path: Optional[Path] = None, deep: bool = False
    ) -> List[GPGKey]:
        """Return the allowed gpg keys of the path.

        * For files it analyzes the gpg data if deep is enabled otherwise it
            looks at the parent .gpg-id file like with directories.
        * For directories it traverses the paths to find the first .gpgid file,
            if the auth store has access information of that file it uses that,
            else it will return the content of the gpg-id file.

        If the `path` is None, it will check all keys stored in all .gpg-id
        files in the password store.

        Args:
            path: A real path to an element of the pass store.
            deep: Enable to analyze the keys allowed for each file instead of
                trusting the .gpg-id files.
        """
        # Get existent keys
        if path:
            if path.match("*.gpg") and deep:
                keys = self.key.list_recipients(path)
            else:
                if path.match("*.gpg-id"):
                    gpg_id = path
                else:
                    gpg_id = self.auth.gpg_id_file(path)
                try:
                    keys = self.auth.allowed_keys(str(gpg_id))
                except NotFoundError:
                    keys = gpg_id.read_text().splitlines()
        else:
            keys = []
            for gpg_id in self.store_dir.rglob(".gpg-id"):
                keys.extend(self.allowed_keys(gpg_id))

        return list(set(keys))

    def reencrypt(
        self,
    ) -> None:
        """Reencrypt the whole password store."""
        for gpg_id in self.auth.store_dir.rglob(".gpg-id"):
            self.update_gpg_id_file(gpg_id)

        self.reencrypt_directory(str(self.auth_dir))

    def reencrypt_directory(
        self,
        pass_dir_path: str,
    ) -> None:
        """Reencrypt the password files of a directory to match the desired access.

        Args:
            pass_dir_path: internal path of a directory of the password store.
                Not a real Path

        Raises:
            ValueError: When trying to authorize a file.
                If we authorize a file with keys different than the ones
                specified on the .gpg-id file, the next time someone reencrypts
                the file using `pass` directly, the change will be overwritten.
                We could handle this case, but not for the MVP.

        """
        if self.path(pass_dir_path).is_file():
            raise ValueError(
                "Authorizing access to a file is not yet supported, "
                "please use the parent directory."
            )

        # Re-encrypt all the password files
        for path in self._pass_paths(pass_dir_path):
            log.info(f"Reencrypting file {self._pass_path(path)}")
            # As we're changing the access keys to a file, we can't use
            # self.allowed_keys directly on the file as it will only report the
            # keys that can now access the file.
            allowed_keys = self.allowed_keys(path=self.auth.gpg_id_file(path))
            self.key.reencrypt(path, allowed_keys)

    def find_keys(self, identifier: "Identifier") -> List[GPGKey]:
        """Return the gpg keys associated to an identifier.

        Args:
            identifier: Unique identifier of a group or person. It can be the
                group name, person name, email or gpg key.
        """
        keys = self.auth.find_keys(identifier)
        return keys

    def update_gpg_id_file(
        self,
        gpg_id: Union[str, Path],
    ) -> None:
        """Update the GPG keys of a .gpg-id file to match the auth store access.

        Args:
            gpg_id: path to a password store .gpg-id file
        """
        keys = []
        if not isinstance(gpg_id, Path):
            gpg_id_file = Path(gpg_id)
        else:
            gpg_id_file = gpg_id
        log.info(f"Updating the keys stored in {gpg_id}")
        keys.extend(self.allowed_keys(gpg_id_file))
        gpg_id_file.write_text("\n".join(set(keys)) + "\n", encoding="utf-8")

    def can_decrypt(self, path: Path) -> bool:
        """Test if the user can decrypt a file.

        Args:
            path: Path to the file to decrypt.
        """
        return self.key.can_decrypt(path)

    @property
    def key_id(self) -> str:
        """Return the gpg key id used by the password store user.

        Compare the private keys stored in the keys store with the keys used in
        the password storage.

        Raises:
            NotFoundError: If the user key is not between the allowed keys.
            TooManyError: If the matching algorithm returns more than one key,
                which would be a bug.
        """
        keystore_keys = self.key.private_key_fingerprints
        matching_keys = list(set(keystore_keys) & set(self.allowed_keys()))

        if len(matching_keys) == 1:
            return matching_keys[0]

        if len(matching_keys) == 0:
            log.warning(
                "The user gpg key was not found between the allowed keys in the "
                "password store"
            )
            if len(keystore_keys) == 1:
                return keystore_keys[0]
            raise TooManyError(
                "There is more than one private key in your store and "
                "none is allowed in the password store"
            )
        raise TooManyError(
            "There were more than 1 available gpg keys that is used "
            f"in the repository. Matching keys are: {matching_keys}"
        )

    @staticmethod
    def all_keys(store_dir: Path) -> List[str]:
        """Return all the gpg keys used by the password store."""
        keys = []

        for gpg_id in store_dir.rglob(".gpg-id"):
            keys.extend(gpg_id.read_text().splitlines())

        return list(set(keys))

    def _pass_paths(self, pass_dir_path: Optional[str] = None) -> List[Path]:
        """Return all the password files of a pass directory.

        Args:
            pass_dir_path: internal path of a directory of the password store.
                Not a real Path. If None it will take the root of the password
                store
        """
        return sorted(self.path(pass_dir_path, is_dir=True).rglob("*.gpg"))

    def _pass_path(self, path: Path) -> str:
        """Return the pass representation of a real path.

        It's the reverse of self.path

        Args:
            path: Path to a real directory or file.
        """
        pass_path = re.sub(rf"{self.store_dir}/?", "", str(path))

        if path.is_file():
            pass_path = pass_path.replace(".gpg", "")

        return pass_path

    def change_group_users(
        self,
        group_name: str,
        add_identifiers: Optional[List["Identifier"]] = None,
        remove_identifiers: Optional[List["Identifier"]] = None,
    ) -> None:
        """Change the list of users of an existent group.

        It also reencrypts the passwords associated to that group.

        Args:
            group_name: Group to change
            add_identifiers: Unique identifiers of users to add. It can be user
                names, emails or gpg keys.
            remove_identifiers: Unique identifiers of users to remove. It can
                be the user names, emails or gpg keys.

        Raises:
            EncryptionError: When there was an error reencrypting the files
                when changing the access
        """
        add_identifiers = add_identifiers or []
        remove_identifiers = remove_identifiers or []

        log.debug("Update the group users in the auth store")
        auth_store_changed = self.auth.change_group_users(
            group_name=group_name,
            add_identifiers=add_identifiers,
            remove_identifiers=remove_identifiers,
        )

        if not auth_store_changed:
            return

        log.debug("Reencrypt the passwords that the group has access to")
        start_dir = self.store_dir / self.auth_dir
        for gpg_id in start_dir.rglob(".gpg-id"):
            pass_path = self._pass_path(gpg_id.parent)
            if self.has_access(pass_path, group_name):
                self.change_access(
                    pass_dir_path=pass_path,
                    add_identifiers=add_identifiers,
                    remove_identifiers=remove_identifiers,
                    auth_upstream_change=auth_store_changed,
                )

    def access(self, identifier: "Identifier", deep: bool = False) -> List[str]:
        """Get a list of passwords the entity identified by identifier has access to.

        It only analyzes the passwords that are in the subtree where the
        .auth.yaml file lives.

        Args:
            identifier: Unique identifier of a group or person. It can be the
                group name, person name, email or gpg key.

            deep: Enable to analyze the keys allowed for each file instead of
                trusting the .gpg-id files.

        Returns:
            List of `pass` paths that the entity has access to.

        Raises:
            NotFoundError: If the identifier doesn't match any known GPG keys
        """
        return [
            self._pass_path(path)
            for path in self._pass_paths(str(self.auth_dir))
            if self.has_access(self._pass_path(path), identifier, deep)
        ]

    def has_access(
        self,
        pass_path: str,
        identifier: Optional["Identifier"] = None,
        deep: bool = False,
    ) -> bool:
        """Return if the user of the password store has access to an element of the store.

        If the identifier is None it will assume that we want to check the
        access of the user that initialize the password store.

        * For files it tries to decrypt them.
        * For directories it checks if the active GPG key is in the allowed
            keys of the .gpgid file.

        If identifier is not None, it will check if the entity represented by
        the identified has access to the element in the store.

        * If it's a group it will check if all the gpg keys are allowed and the group is
            allowed in the auth store.
        * If it's a user it will check if it's gpg key is allowed.

        Args:
            pass_path: internal path of the password store. Not a real Path
            identifier: Unique identifier of a group or person. It can be the
                group name, person name, email or gpg key.
            deep: Enable to analyze the keys allowed for each file instead of
                trusting the .gpg-id files.

        Raises:
            NotFoundError: If the identifier doesn't match any known GPG keys
        """
        path = self.path(pass_path)

        log.debug(f"Checking access of {pass_path}")
        # If we want to check the active user
        if not identifier:
            if path.is_file():
                return self.can_decrypt(path)
            keys = [self.key_id]
        else:
            keys = self.auth.find_keys(identifier)

            if len(keys) == 0:
                try:
                    keys = [self.key.find_key(identifier).id_]
                except NotFoundError as error:
                    log.error(
                        f"Coudn't find a valid GPG key for {identifier} in your store"
                    )
                    raise error
        try:
            allowed_keys = self.allowed_keys(path, deep)
            all_keys_allowed = all(key in allowed_keys for key in keys)
        except NotFoundError:
            # if self.key_id raises a NotFoundError is because there is no key that
            # is allowed
            return False

        if not all_keys_allowed:
            return False

        # If it's a group we need to check that the group name is in the access list.
        if identifier:
            try:
                return self.auth.has_access(path, identifier)
            except NotFoundError:
                return False

        return True

    # R0913: too many arguments 6/5, but self shouldn't count :P
    def change_access(  # noqa: R0913
        self,
        pass_dir_path: str,
        add_identifiers: Optional[List["Identifier"]] = None,
        remove_identifiers: Optional[List["Identifier"]] = None,
        ignore_parent: bool = False,
        auth_upstream_change: bool = False,
    ) -> None:
        """Authorize or revoke a group or person to a directory of the password store.

        It will also tweak the `.gpg-id` file to specify the desired access and
        it will reencrypt the files of that directory.

        Args:
            pass_dir_path: internal path of a directory of the password store.
                 Not a real Path
            add_identifiers: Unique identifiers of groups or people to authorize.
                It can be the group name, person name, email or gpg key. Can be
                used in addition to `keys`.
            remove_identifiers: Unique identifiers of groups or people to revoke.
                It can be the group name, person name, email or gpg key. Can be
                used in addition to `keys`.
            ignore_parent: Ignore the access permissions defined in the parent .gpg-id.
                It shouldn't be True by default because it will risk locking
                yourself out.
            auth_upstream_change: If there was a change in the auth done by any
                operations before the call of this function

        Raises:
            ValueError: When trying to authorize a file.
                If we authorize a file with keys different than the ones specified on
                the .gpg-id file, the next time someone reencrypts the file using `pass`
                directly, the change will be overwritten. We could handle this case, but
                not for the MVP.
            EncryptionError: When there was an error reencrypting the files
                when changing the access
        """
        if self.path(pass_dir_path).is_file():
            raise ValueError(
                "Changing access to a file is not yet supported, "
                "please use the parent directory."
            )
        log.info(f"Updating access to {pass_dir_path}")

        gpg_id = f"{self.path(pass_dir_path)}/.gpg-id"

        auth_changed = self.auth.change_access(
            gpg_id=gpg_id,
            add_identifiers=add_identifiers,
            remove_identifiers=remove_identifiers,
            ignore_parent=ignore_parent,
        )

        if auth_changed or auth_upstream_change:
            self.update_gpg_id_file(gpg_id)
            self.reencrypt_directory(pass_dir_path)
