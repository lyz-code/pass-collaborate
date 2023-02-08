"""Test the implementation of the PassStore."""

from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from pass_collaborate.exceptions import NotFoundError

if TYPE_CHECKING:
    from pass_collaborate.adapters import PassStore

@pytest.mark.parametrize(
    ("in_", "out"),
    [
        ("web", "/web"),  # Transform a directory path
        (None, ""),  # Transform None
        ("bastion", "/bastion.gpg"),  # Transform a file path
    ],
)
def test_path_returns_the_expected_results(
    pass_: "PassStore", in_: str, out: str
) -> None:
    """
    Given: A configured PassStore
    When: transforming the incoming paths with the path method
    Then: the expected results are returned
    """
    result = pass_.path(in_)

    assert result == Path(f"{pass_.store_dir}{out}")


@pytest.mark.parametrize(
    ("in_", "out"),
    [
        ("web", "web"),  # Transform a directory path
        ("", ""),  # Transform None
        ("bastion.gpg", "bastion"),  # Transform a file path
    ],
)
def test_pass_path_returns_the_expected_results(
    pass_: "PassStore", in_: str, out: str
) -> None:
    """
    Given: A configured PassStore
    When: transforming the incoming paths with the pass_path method
    Then: the expected results are returned
    """
    path = pass_.store_dir / in_

    result = pass_._pass_path(path)

    assert result == out


def test_path_raises_error_if_not_found(pass_: "PassStore") -> None:
    """
    Given: A configured PassStore
    When: transforming the incoming paths with the path method for an inexistent path
    Then: An error is raised
    """
    with pytest.raises(
        NotFoundError,
        match="Could not find the element inexistent_path in the password store",
    ):
        pass_.path("inexistent_path")


def test_authorize_raises_error_if_file(pass_: "PassStore") -> None:
    """
    Given: A configured PassStore
    When: trying to authorize a file instead of a directory
    Then: an error is raised.

    If we authorize a file with keys different than the ones specified on the .gpg-id
    file, the next time someone reencrypts the file using `pass` directly, the change
    will be overwritten. We could handle this case, but not for the MVP
    """
    with pytest.raises(
        ValueError,
        match=(
            "Authorizing access to a file is not yet supported, "
            "please use the parent directory."
        ),
    ):
        pass_.authorize("bastion", "developer")


def test_key_id_returns_error_if_no_key_is_valid(pass_attacker: "PassStore") -> None:
    """
    Given: A configured PassStore with the key of a user that should not have access
    When: Trying to get the key id that works for the password store
    Then: An exception is raised.
    """
    with pytest.raises(
        NotFoundError,
        match="The user gpg key was not found between the allowed keys",
    ):
        pass_attacker.key_id


def test_pass_has_access_to_directory(
    pass_: "PassStore", pass_dev: "PassStore"
) -> None:
    """
    Given: A configured PassStore
    When: checking the access to a directory that only the admin should have access.
    Then: return true for the admin, false for the developer
    """
    result = {
        "admin": pass_.has_access("web"),
        "developer": pass_dev.has_access("web"),
    }

    assert result["admin"]
    assert not result["developer"]
