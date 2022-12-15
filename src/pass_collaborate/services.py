"""Define all the orchestration functionality required by the program to work.

Classes and functions that connect the different domain model objects with the adapters
and handlers to achieve the program's purpose.
"""

import logging
from typing import TYPE_CHECKING

from .exceptions import NotFoundError, TooManyError

if TYPE_CHECKING:
    from .adapters import AuthStore, KeyStore, PassStore

log = logging.getLogger(__name__)


def has_access(pass_: "PassStore", key: "KeyStore", pass_path: str) -> bool:
    """Return if the user of the password store has access to an element of the store.

    * For files it tries to decrypt it.
    * For directories it checks if our key is in the allowed keys of the .gpgid
        file.

    Args:
        pass_: Adapter of the password store of the user to test
        key: Adapter of the gpg key store of the user to test.
        pass_path: internal path of the password store. Not a real Path
    """
    path = pass_.path(pass_path)

    if path.is_file():
        return key.can_decrypt(path)

    try:
        return get_key_id(pass_, key) in pass_.allowed_keys(path)
    except NotFoundError:
        # if self.key_id raises a NotFoundError is because there is no key that
        # is allowed
        return False


def get_key_id(pass_: "PassStore", key: "KeyStore") -> str:
    """Return the gpg key id used by the password store user.

    Compare the private keys stored in the keys store with the keys used in the
    password storage.

    Args:
        pass_: Adapter of the password store of the user to test.
        key: Adapter of the gpg key store of the user to test.

    Raises:
        NotFoundError: If the user key is not between the allowed keys.
        TooManyError: If the matching algorithm returns more than one key, which
            would be a bug.
    """
    keystore_keys = key.private_key_fingerprints
    matching_keys = list(set(keystore_keys) & set(pass_.allowed_keys()))

    if len(matching_keys) == 1:
        return matching_keys[0]

    if len(matching_keys) == 0:
        raise NotFoundError("The user gpg key was not found between the allowed keys")
    raise TooManyError(
        "There were more than 1 available gpg keys that is used "
        f"in the repository. Matching keys are: {matching_keys}"
    )


def authorize(auth: "AuthStore", identifier: str, pass_path: str) -> None:
    """Authorize a group or person to a directory of the password store.

    And save the data in the AuthStore

    Args:
        id_: Unique identifier of a group or person. It can be the group name, person
            name, email or gpg key.
        path: directory to give access to.
    """
    # Get the keys to encrypt the directory files
    # From AuthStore get the existent keys
    # From AuthStore get the new keys from the id_
    new_keys = auth.get_keys(identifier) + key.get_keys(identifier)
    # As fallback:
    #   From KeyStore get the existent keys
    #   From KeyStore get the new keys from the id_

    # Reencrypt the underlying files
    # With PassStore encrypt with the new keys

    # Save the information of who is authorized
    # With AuthStore update the .auth.yaml file
