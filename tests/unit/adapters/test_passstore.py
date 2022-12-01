"""Test the implementation of the PassStore."""

from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pass_collaborate.adapters import PassStore


def test_pass_has_access_to_directory(
    pass_: "PassStore", pass_dev: "PassStore"
) -> None:
    """
    Given: A configured PassStore
    When: checking the access to a directory that only the admin should have access.
    Then: return true for the admin, false for the developer
    """
    result = {"admin": pass_.has_access("web"), "developer": pass_dev.has_access("web")}

    assert result["admin"]
    assert not result["developer"]


def test_key_id_returns_error_if_no_key_is_valid(pass_attack: "PassStore") -> None:
    """
    Given: A configured PassStore for a user that should not have access
    When: Trying to get the key id that works for the password store
    Then: An exception is raised.
    """
    with pytest.raises(
        ValueError,
        match=(
            "There were more or less than 1 available gpg keys that is used "
            "in the repository. Matching keys are: "
        ),
    ):
        # W0104: Statement seems to have no effect (pointless-statement). (/ﾟДﾟ)/
        pass_attack.key_id  # noqa: W0104
