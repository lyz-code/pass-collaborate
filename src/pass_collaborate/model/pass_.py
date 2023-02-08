"""Define the data models of the password store."""

import logging
from contextlib import suppress
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional

from pydantic import BaseModel, root_validator  # noqa: E0611

from ..adapters import KeyStore
from ..exceptions import NotFoundError, TooManyError
from .auth import AuthStore
from .key import GPGKey

log = logging.getLogger(__name__)


class PassStore(BaseModel):
    """Define the adapter of the `pass` password store.

    I've thought of using [passpy](https://github.com/bfrascher/passpy) but it doesn't
    look maintained anymore.

    Args:
        store_dir: Directory where the `pass` password store data lives.
        key_dir: Directory where the `gnupg` data lives.
    """

    store_dir: Path
    key_dir: Path
    key: KeyStore
    auth: AuthStore

    class Config:
        """Configure the pydantic model."""

        arbitrary_types_allowed = True

    @root_validator(pre=True)
    @classmethod
    def set_adapters(cls, values: Dict[str, Any]) -> Dict[str, Any]:
        """Set the adapters."""
        values["key"] = KeyStore(key_dir=values["key_dir"])

        auth = AuthStore()
        auth_file = auth.check_auth_file(values["store_dir"])
        auth.load(auth_file)
        values["auth"] = auth

        return values

        return auth

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
        self,
        path: Optional[Path] = None,
        add_keys: Optional[List[str]] = None,
        remove_keys: Optional[List[str]] = None,
    ) -> List[str]:
        """Return the allowed gpg keys of the path.

        * For files it analyzes the gpg data.
        * For directories it traverses the paths to find the first .gpgid file,
            returning it's content.

        If the `path` is None, it will check all keys stored in all .gpg-id files in the password store.

        Args:
            path: A real path to an element of the pass store.
            add_keys: List of keys to add to the allowed_keys
            remove_keys: List of keys to remove from the allowed_keys
        """
        add_keys = add_keys or []
        remove_keys = remove_keys or []

        # Get existent keys
        if path:
            existent_keys = self._gpg_id_file(path).read_text().splitlines()
        else:
            existent_keys = []
            for gpg_id in self.store_dir.rglob(".gpg-id"):
                existent_keys.extend(gpg_id.read_text().splitlines())

        # Add or remove keys
        keys = list(set(existent_keys + add_keys))
        for key in remove_keys:
            with suppress(ValueError):
                keys.remove(key)

        return keys

    def authorize(
        self,
        pass_dir_path: str,
        id_: Optional[str] = None,
        keys: Optional[List[GPGKey]] = None,
    ) -> None:
        """Authorize a group or person to a directory of the password store.

        It will tweak the `.gpg-id` file to specify the desired access and it will reencrypt the files of that directory.

        Args:
            pass_dir_path: internal path of a directory of the password store.
                Not a real Path
            id_: Unique identifier of a group or person. It can be the group name,
                person name, email or gpg key. Can be used in addition to `keys`.
            keys: List of new keys to authorize. Can be used in addition to `id_`.

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

        # Deduce the new keys to add
        keys = keys or []
        if id_:
            keys.extend(self.find_keys(id_))

        if keys == []:
            return

        # Re-encrypt all the password files
        for path in self._pass_paths(pass_dir_path):
            log.info(
                f"Authorizing {id_ or ','.join(keys)} to access password {self._pass_path(path)}"
            )
            self.key.encrypt(path, self.allowed_keys(path=path, add_keys=keys))

        # Edit the .gpg-id file to edit the authorization
        self.change_gpg_id_keys(pass_dir_path, add_keys=keys)

    def revoke(
        self,
        pass_dir_path: str,
        id_: Optional[str] = None,
        keys: Optional[List[GPGKey]] = None,
    ) -> None:
        """Revoke access of a group or person to a directory of the password store.

        It will tweak the `.gpg-id` file to specify the desired access and it will reencrypt the files of that directory.

        Args:
            pass_dir_path: internal path of a directory of the password store.
                Not a real Path
            id_: Unique identifier of a group or person. It can be the group name,
                person name, email or gpg key. Can be used in addition to `keys`.
            keys: List of new keys to revoke. Can be used in addition to `id_`.

        Raises:
            ValueError: When trying to authorize a file.
                If we authorize a file with keys different than the ones specified on
                the .gpg-id file, the next time someone reencrypts the file using `pass`
                directly, the change will be overwritten. We could handle this case, but
                not for the MVP.

        """
        if self.path(pass_dir_path).is_file():
            raise ValueError(
                "Revoking access to a file is not yet supported, "
                "please use the parent directory."
            )

        # Deduce the keys to remove
        keys = keys or []
        if id_:
            keys.extend(self.find_keys(id_))

        if keys == []:
            return

        # Re-encrypt all the password files
        for path in self._pass_paths(pass_dir_path):
            log.info(
                f"Revoking {id_ or ','.join(keys)} to access password {self._pass_path(path)}"
            )
            self.key.encrypt(path, self.allowed_keys(path=path, remove_keys=keys))

        # Edit the .gpg-id file to edit the authorization
        self.change_gpg_id_keys(pass_dir_path, add_keys=keys)

    def find_keys(self, id_: str) -> List[GPGKey]:
        """Return the gpg keys associated to an identifier.

        Args:
            id_: Unique identifier of a group or person. It can be the group name,
                person name, email or gpg key.
        """
        keys = self.auth.find_keys(id_)
        return keys

    def change_gpg_id_keys(
        self,
        pass_dir_path: str,
        add_keys: Optional[List[GPGKey]] = None,
        remove_keys: Optional[List[GPGKey]] = None,
    ) -> None:
        """Add GPG keys to the .gpg-id file of a `pass` password store directory.

        Args:
            pass_dir_path: internal path of a directory of the password store.
                Not a real Path
            add_keys: List of keys to add to the allowed_keys
            remove_keys: List of keys to remove from the allowed_keys
        """
        add_keys = add_keys or []
        remove_keys = remove_keys or []
        path = self.path(pass_dir_path)
        desired_gpg_id = path / ".gpg-id"
        active_gpg_id = self._gpg_id_file(path)

        if desired_gpg_id != active_gpg_id:
            old_keys = active_gpg_id.read_text().splitlines()
        else:
            old_keys = desired_gpg_id.read_text().splitlines()

        # Add or remove keys
        keys = list(set(old_keys + add_keys))
        for key in remove_keys:
            with suppress(ValueError):
                keys.remove(key)

        desired_gpg_id.write_text("\n".join(keys))

    def can_decrypt(self, path: Path) -> bool:
        """Test if the user can decrypt a file.

        Args:
            path: Path to the file to decrypt.
        """
        return self.key.can_decrypt(path)

    @property
    def key_id(self) -> str:
        """Return the gpg key id used by the password store user.

        Compare the private keys stored in the keys store with the keys used in the
        password storage.

        Raises:
            NotFoundError: If the user key is not between the allowed keys.
            TooManyError: If the matching algorithm returns more than one key, which
                would be a bug.
        """
        keystore_keys = self.key.private_key_fingerprints
        matching_keys = list(set(keystore_keys) & set(self.allowed_keys()))

        if len(matching_keys) == 1:
            return matching_keys[0]

        if len(matching_keys) == 0:
            raise NotFoundError(
                "The user gpg key was not found between the allowed keys"
            )
        raise TooManyError(
            "There were more than 1 available gpg keys that is used "
            f"in the repository. Matching keys are: {matching_keys}"
        )

    def _pass_paths(
        self, pass_dir_path: Optional[str] = None
    ) -> Generator[Path, None, None]:
        """Return all the password files of a pass directory.

        Args:
            pass_dir_path: internal path of a directory of the password store.
                Not a real Path. If None it will take the root of the password store
        """
        pass_dir_path = pass_dir_path or self.store_dir

        return self.path(pass_dir_path, is_dir=True).rglob("*.gpg")

    def _pass_path(self, path: Path) -> str:
        """Return the pass representation of a real path.

        It's the reverse of self.path

        Args:
            path: Path to a real directory or file.
        """
        pass_path = str(path).replace(f"{self.store_dir}/", "")

        if path.is_file():
            pass_path = pass_path.replace(".gpg", "")

        return pass_path

    def has_access(self, pass_path: str, identifier: Optional[str] = None) -> bool:
        """Return if the user of the password store has access to an element of the store.

        If the identifier is None it will assume that we want to check the access of the user that initialize the password store.

        * For files it tries to decrypt them.
        * For directories it checks if the active GPG key is in the allowed keys of the .gpgid
            file.

        If identifier is not None, it will check if the entity represented by the identified has access to the element in the store.

        * If it's a group it will check if all the gpg keys are allowed.
        * If it's a user it will check if it's gpg key is allowed.

        Args:
            pass_path: internal path of the password store. Not a real Path
            identifier: Unique identifier of a group or person. It can be the group name,
                person name, email or gpg key.
        """
        path = self.path(pass_path)

        # If we want to check the active user
        if not identifier:
            if path.is_file():
                return self.can_decrypt(path)
            keys = [self.key_id]
        else:
            keys = self.auth.find_keys(identifier)

        try:
            allowed_keys = self.allowed_keys(path)
            return all(key in allowed_keys for key in keys)
        except NotFoundError:
            # if self.key_id raises a NotFoundError is because there is no key that
            # is allowed
            return False

    def change_group_users(
        self,
        group_name: str,
        add_identifiers: Optional[List[str]] = None,
        remove_identifiers: Optional[List[str]] = None,
    ) -> None:
        """Change the list of users of an existent group.

        It also reencrypts the passwords associated to that group.

        Args:
            group_name: Group to change
            add_identifiers: Unique identifiers of users to add. It can be user names, emails or gpg keys.
            remove_identifiers: Unique identifiers of users to remove. It can be the user names, emails or gpg keys.
        """
        add_identifiers = add_identifiers or []
        remove_identifiers = remove_identifiers or []

        # Update the auth store
        new_keys, remove_keys = self.auth.change_group_users(
            group_name=group_name,
            add_identifiers=add_identifiers,
            remove_identifiers=remove_identifiers,
        )

        # Reencrypt the passwords that the group has access to
        for gpg_id in self.store_dir.rglob(".gpg-id"):
            pass_path = self._pass_path(gpg_id.parent)
            if self.has_access(pass_path, group_name):
                self.authorize(pass_dir_path=pass_path, keys=new_keys)
                self.revoke(pass_dir_path=pass_path, keys=remove_keys)

    def access(self, identifier: str) -> List[str]:
        """Get a list of passwords the entity identified by identifier has access to.

        Args:
            identifier: Unique identifier of a group or person. It can be the group name,
                person name, email or gpg key.

        Returns:
            List of `pass` paths that the entity has access to.
        """
        return [
            self._pass_path(path)
            for path in self._pass_paths()
            if self.has_access(self._pass_path(path), identifier)
        ]
