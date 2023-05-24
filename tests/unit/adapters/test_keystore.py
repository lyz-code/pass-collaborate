"""Test the KeyStore implementation."""

from pathlib import Path
from typing import TYPE_CHECKING

import pytest
import sh

from pass_collaborate.adapters import KeyStore
from pass_collaborate.exceptions import NotFoundError

if TYPE_CHECKING:
    from pass_collaborate.model.auth import User


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
        match="Could not find the file to decrypt in /tmp/this-doesnt-exist",
    ):
        key.decrypt(Path("/tmp/this-doesnt-exist"))


def test_can_decrypt_a_file(key: KeyStore, work_dir: Path) -> None:
    """
    Given: A keystore adapter
    When: decrypting a file that we have permission to read
    Then: the output is the expected one
    """
    file_to_decrypt = work_dir / ".password-store" / "bastion.gpg"

    result = key.decrypt(file_to_decrypt)

    assert result == "Qqq*yEbb.]W@c?sDJW&&ym_CR\n"


def test_can_encrypt_a_file(key: KeyStore, work_dir: Path) -> None:
    """
    Given: A keystore adapter
    When: encrypting a file
    Then: the keystore is able to decrypt it and `pass` command too
    """
    text = "this is a test"
    file_to_encrypt = work_dir / ".password-store" / "new_file.gpg"
    file_to_encrypt.write_text(text)

    key.encrypt(file_to_encrypt, [key.private_key_fingerprints[0]])  # act

    assert key.decrypt(file_to_encrypt) == text
    pass_command = sh.Command("pass")
    pass_result = pass_command(
        "show",
        "new_file",
        _env={
            "PASSWORD_STORE_DIR": str(work_dir / ".password-store"),
            "PASSWORD_STORE_GPG_OPTS": f"--homedir {str(work_dir/ 'gpg' / 'admin')}",
        },
    )
    assert pass_result == text


def test_can_reencrypt_a_file(
    key: KeyStore, work_dir: Path, admin: "User", developer: "User"
) -> None:
    """
    Given: A keystore adapter and an encrypted file
    When: reencrypting a file with other keys
    Then: the keystore is able to decrypt it and `pass` command too
    """
    text = "this is a test"
    file_to_encrypt = work_dir / ".password-store" / "new_file.gpg"
    file_to_encrypt.write_text(text)
    key.encrypt(file_to_encrypt, [admin.key])

    key.reencrypt(file_to_encrypt, [admin.key, developer.key])  # act

    assert key.decrypt(file_to_encrypt) == text
    pass_command = sh.Command("pass")
    pass_result = pass_command(
        "show",
        "new_file",
        _env={
            "PASSWORD_STORE_DIR": str(work_dir / ".password-store"),
            "PASSWORD_STORE_GPG_OPTS": f"--homedir {str(work_dir/ 'gpg' / 'admin')}",
        },
    )
    assert pass_result == text


def test_can_list_recipients_of_file(key: KeyStore, work_dir: Path) -> None:
    """
    Given: A keystore adapter
    When: listing the keys that can decrypt a file
    Then: the output is the expected one
    """
    file_to_check = work_dir / ".password-store" / "bastion.gpg"

    result = key.list_recipients(file_to_check)

    assert result == [key.private_key_fingerprints[0]]


def test_find_key_works_with_short_id(key: KeyStore, admin: "User") -> None:
    """
    Given: A keystore adapter
    When: Calling find_key with the short id of a gpg key
    Then: The desired key is found
    """
    result = key.find_key("DECE5B3C889F13DE")

    assert result.id_ == admin.key
