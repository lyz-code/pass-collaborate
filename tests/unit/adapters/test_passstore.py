"""Test the implementation of the PassStore."""

import shutil
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from pass_collaborate.exceptions import NotFoundError

if TYPE_CHECKING:
    from pass_collaborate.model.auth import User
    from pass_collaborate.model.pass_ import PassStore


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


def test_path_supports_files_with_dots(pass_: "PassStore") -> None:
    """
    Given: A configured PassStore
    When: transforming a path of a file with dots in the name
    Then: the expected result is returned
    """
    shutil.move(
        str(pass_.store_dir / "bastion.gpg"), str(pass_.store_dir / "the.bastion.gpg")
    )

    result = pass_.path("the.bastion")

    assert result == pass_.store_dir / "the.bastion.gpg"


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
    # W0212 Access to a protected member _pass_path of a client class.

    result = pass_._pass_path(path)  # noqa: W0212

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
            "Changing access to a file is not yet supported, "
            "please use the parent directory."
        ),
    ):
        pass_.change_access("bastion", ["developer"])


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


def test_pass_has_access_group_is_not_equal_to_their_keys(
    pass_: "PassStore", admin: "User"
) -> None:
    """
    Given: A configured PassStore and a path whose access is allowed for a gpg key
    When: checking the access to that directory for a group that only has that gpg key
    Then: return false as the user is allowed but not the group
    """
    pass_.auth.add_group(name="developers", user_ids=[admin.email])

    result = pass_.has_access("", "developers")

    assert not result


def test_pass_update_gpg_id_file_ends_in_newline(pass_: "PassStore") -> None:
    r"""
    Given: A pass store
    When: Using the update_gpg_id_file method
    Then: The created file ends in a \n

    Otherwise the last key in the file is not used by pass when encrypting new files.
    """
    gpg_id_file = pass_.store_dir / ".gpg-id"

    pass_.update_gpg_id_file(gpg_id_file)  # act

    assert gpg_id_file.read_text()[-1] == "\n"
