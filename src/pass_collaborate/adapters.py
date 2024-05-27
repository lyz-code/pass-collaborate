"""Define the adapters of the key stores."""

import re
from pathlib import Path
from typing import TYPE_CHECKING, List

from gnupg import GPG
from pydantic import BaseModel

from .exceptions import DecryptionError, EncryptionError, NotFoundError, TooManyError

if TYPE_CHECKING:
    from .model.key import GPGKey


class Key(BaseModel):
    """Model the relevant data of a GPG key."""

    id_: str
    name: str
    email: str
    short_key: str

    def match(self, identifier: str) -> bool:
        """Check if the identifier matches the current key.

        It will check the string against the different key properties.
        """
        return any(
            getattr(self, attribute) == identifier
            for attribute in ["id_", "name", "email", "short_key"]
        )


class KeyStore:
    """Define the adapter of the `gpg` key store."""

    def __init__(self, key_dir: Path, gpg_binary: str = "/usr/bin/gpg2") -> None:
        """Set the gpg connector.

        Args:
            key_dir: Path to the GnuPG home directory where your GPG keys live.

        Raises:
            NotFoundError: If the directory doesn't exist
        """
        key_dir = key_dir.expanduser()
        if not key_dir.is_dir():
            raise NotFoundError(f"{key_dir} is not a directory that holds gnupg data.")
        self.key_dir = key_dir
        self.gpg = GPG(gnupghome=key_dir, gpgbinary=gpg_binary)

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

    def encrypt(self, path: Path, keys: List["GPGKey"]) -> None:
        """Encrypt a file for a list of keys.

        Args:
            path: Path to the file to encrypt.
            keys: GPG keys used to encrypt the file.

        Raise:
           EncryptionError: if there is any problem when encrypting the file.
        """
        encrypted_data = self.gpg.encrypt_file(str(path), keys)
        if encrypted_data.ok:
            path.write_bytes(encrypted_data.data)
        else:
            # E1101 Instance of 'Crypt' has no 'stderr' member (no-member). But it does
            raise EncryptionError(encrypted_data.stderr)  # noqa: E1101

    def reencrypt(self, path: Path, keys: List["GPGKey"]) -> None:
        """Reencrypt a file for a list of keys.

        Args:
            path: Path to the file to reencrypt.
            keys: GPG keys used to encrypt the file.

        Raise:
           EncryptionError: if there is any problem when encrypting the file.
        """
        data = self.decrypt(path)
        encrypted_data = self.gpg.encrypt(data, keys)
        if encrypted_data.ok:
            path.write_bytes(encrypted_data.data)
        else:
            # E1101 Instance of 'Crypt' has no 'stderr' member (no-member). But it does
            raise EncryptionError(encrypted_data.stderr)  # noqa: E1101

    def list_recipients(self, path: Path) -> List["GPGKey"]:
        """List the keys that can decrypt a file.

        Args:
            path: Path to the file to check.
        """
        keys = []
        for short_key in self.gpg.get_recipients_file(str(path)):
            try:
                keys.append(self.gpg.list_keys(keys=[short_key])[0]["fingerprint"])
            except IndexError as error:
                raise NotFoundError(
                    f"Could not find gpg key with id {short_key}"
                ) from error

        return keys

    @property
    def private_key_fingerprints(self) -> List[str]:
        """Return the IDs of the private keys."""
        return [key["fingerprint"] for key in self.gpg.list_keys(True)]

    @property
    def public_key_fingerprints(self) -> List[Key]:
        """Return the IDs of the public keys.

        It will only use the first id that it finds.
        """
        keys = []
        for key in self.gpg.list_keys():
            match = re.match(r"(?P<name>.*) <(?P<email>.*)>", key["uids"][0])
            if match is None:
                raise ValueError(
                    "Could not extract the name or email from the gpg key "
                    f"{key['keyid']} information"
                )
            keys.append(
                Key(
                    id_=key["fingerprint"],
                    name=match["name"],
                    email=match["email"],
                    short_key=key["keyid"],
                )
            )

        return keys

    def find_key(self, identifier: str) -> Key:
        """Return the key that matches the identifier.

        Args:
            identifier: GPG key name, email or fingerprint

        Raises:
            NotFoundError: If the identifier doesn't match any available public keys.
            TooManyError: If more than one available public key match the identifier.
        """
        keys = []
        for key in self.public_key_fingerprints:
            if key.match(identifier):
                keys.append(key)

        if len(keys) == 1:
            return keys[0]
        if len(keys) == 0:
            raise NotFoundError(f"No key found for {identifier}")
        raise TooManyError(f"More than one key matched the identifier {identifier}")
