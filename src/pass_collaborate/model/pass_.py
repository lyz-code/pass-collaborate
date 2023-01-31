"""Define the data models of the password store."""
import logging
import os
from pathlib import Path
from typing import Generator, List, Optional, Annotated, Dict, Any

from ..exceptions import DecryptionError, NotFoundError, TooManyError
from ..adapters import KeyStore
from .auth import AuthStore
from .key import GPGKey

from pydantic import BaseModel, EmailStr, Field, root_validator  # noqa: E0611


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
        values['key'] = KeyStore(key_dir=values['key_dir'])

        auth = AuthStore()
        auth_file = auth.check_auth_file(values['store_dir'])
        auth.load(auth_file)
        values['auth'] = auth

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
            raise NotFoundError("The user gpg key was not found between the allowed keys")
        raise TooManyError(
            "There were more than 1 available gpg keys that is used "
            f"in the repository. Matching keys are: {matching_keys}"
        )

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


    def has_access(self, pass_path: str) -> bool:
        """Return if the user of the password store has access to an element of the store.

        * For files it tries to decrypt it.
        * For directories it checks if our key is in the allowed keys of the .gpgid
            file.

        Args:
            pass_: Adapter of the password store of the user to test
            key: Adapter of the gpg key store of the user to test.
            pass_path: internal path of the password store. Not a real Path
        """
        path = self.path(pass_path)

        if path.is_file():
            return self.can_decrypt(path)

        try:
            return self.key_id in self.allowed_keys(path)
        except NotFoundError:
            # if self.key_id raises a NotFoundError is because there is no key that
            # is allowed
            return False


