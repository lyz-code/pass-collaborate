"""Tests the service layer."""

from typing import TYPE_CHECKING

import pytest

from pass_collaborate import exceptions, services

if TYPE_CHECKING:
    from pass_collaborate.adapters import KeyStore, PassStore


def test_pass_has_access_to_directory(
    pass_: "PassStore", key: "KeyStore", key_dev: "KeyStore"
) -> None:
    """
    Given: A configured PassStore
    When: checking the access to a directory that only the admin should have access.
    Then: return true for the admin, false for the developer
    """
    result = {
        "admin": services.has_access(pass_, key, "web"),
        "developer": services.has_access(pass_, key_dev, "web"),
    }

    assert result["admin"]
    assert not result["developer"]


def test_key_id_returns_error_if_no_key_is_valid(
    pass_: "PassStore", key_attacker: "KeyStore"
) -> None:
    """
    Given: A configured PassStore and a KeyStore of a user that should not have access
    When: Trying to get the key id that works for the password store
    Then: An exception is raised.
    """
    with pytest.raises(
        exceptions.NotFoundError,
        match="The user gpg key was not found between the allowed keys",
    ):
        services.get_key_id(pass_, key_attacker)
