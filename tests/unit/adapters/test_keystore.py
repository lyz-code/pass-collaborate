"""Test the KeyStore implementation."""

from pathlib import Path

import pytest

from pass_collaborate.adapters import KeyStore
from pass_collaborate.exceptions import NotFoundError


def test_create_keystore_raises_exception_if_home_is_not_a_directory() -> None:
    """
    Given: A keystore adapter
    When: initializing it with a directory that doesn't exist
    Then: an exception is thrown
    """
    with pytest.raises(
        NotFoundError,
        match="/tmp/this-doesnt-exist is not a directory that holds gnupg data.",
    ):
        KeyStore(key_dir=Path("/tmp/this-doesnt-exist"))


def test_decrypt_returns_file_not_found(key: KeyStore) -> None:
    """
    Given: A keystore adapter
    When: trying to decrypt a file that doesn't exist.
    Then: raises exception
    """
    with pytest.raises(
        NotFoundError,
        match="No valid data found in /tmp/this-doesnt-exist",
    ):
        key.decrypt(Path("/tmp/this-doesnt-exist"))
