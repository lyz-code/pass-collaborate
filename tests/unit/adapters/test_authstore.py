"""Test the implementation of the AuthStore."""

from contextlib import suppress
from typing import TYPE_CHECKING, List

import pytest

from pass_collaborate.exceptions import NotFoundError, TooManyError
from pass_collaborate.model.auth import Group

from ...factories import UserFactory

if TYPE_CHECKING:
    from pass_collaborate.model.auth import AuthStore, User
    from pass_collaborate.model.key import GPGKey


def test_raises_exception_if_group_exists(auth: "AuthStore") -> None:
    """
    Given: an auth store
    When: creating a group that already exists
    Then: an exception is raised.
    """
    auth.add_group("existent_group")

    with pytest.raises(ValueError, match="The group existent_group already exists."):
        auth.add_group("existent_group")


def test_add_group_without_users(auth: "AuthStore") -> None:
    """
    Given: an auth store
    When: creating a group without users
    Then: the group is created
    """
    result = auth.add_group("No users")

    assert result == Group(name="No users")


def test_get_group_raises_exception(auth: "AuthStore") -> None:
    """
    Given: an auth store
    When: get_group is called on a group that doesn't exist.
    Then: an exception is raised.
    """
    with pytest.raises(NotFoundError, match="The group fight_club doesn't exist."):
        auth.get_group("fight_club")


def test_raises_exception_if_user_exists(auth: "AuthStore") -> None:
    """
    Given: an auth store
    When: creating a user that already exists
    Then: an exception is raised.
    """
    user = UserFactory.build()
    auth.add_user(user.name, user.key, user.email)

    with pytest.raises(ValueError, match=f"The user {user.name} already exists."):
        auth.add_user(user.name, user.key, user.email)


@pytest.mark.parametrize(
    "identifier",
    [
        "Marie",
        "developer@example.org",
        "8DFE8782CD025ED6220D305115575911602DDD94",
    ],
)
def test_get_user_happy_path(
    auth: "AuthStore", developer: "User", identifier: str
) -> None:
    """
    Given: A valid user
    When: getting by the email, key or name
    Then: the user is returned
    """
    auth.add_user(developer.name, developer.key, developer.email)

    result = auth.get_user(identifier)

    assert result == developer


@pytest.mark.parametrize(
    "identifier",
    [
        "developer@example.org",
        "8DFE8782CD025ED6220D305115575911602DDD94",
    ],
)
def test_get_user_raises_exception_if_more_than_one(
    auth: "AuthStore", developer: "User", identifier: str
) -> None:
    """
    Given: A valid user introduced twice
    When: getting by the email, key or name.
    Then: As more than one user matches, raise an exception.
    """
    auth.add_user(developer.name, developer.key, developer.email)
    auth.add_user("Other name", developer.key, developer.email)

    with pytest.raises(
        TooManyError, match="More than one user matched the selected criteria"
    ):
        auth.get_user(identifier)


@pytest.mark.parametrize(
    ("identifier", "out"),
    [
        ("Marie", ["8DFE8782CD025ED6220D305115575911602DDD94"]),
        ("developer@example.org", ["8DFE8782CD025ED6220D305115575911602DDD94"]),
        (
            "8DFE8782CD025ED6220D305115575911602DDD94",
            ["8DFE8782CD025ED6220D305115575911602DDD94"],
        ),
        ("developers", ["8DFE8782CD025ED6220D305115575911602DDD94"]),
        ("not_existent_group_or_user", []),
    ],
)
def test_find_keys_happy_path(
    auth: "AuthStore", developer: "User", identifier: str, out: List["GPGKey"]
) -> None:
    """
    Given: Two valid users and a group
    When: getting by the user email, key or name, or group name, or non matching
    Then: the user is returned
    """
    auth.add_user(developer.name, developer.key, developer.email)
    auth.add_group(name="developers", users=["developer@example.org"])

    result = auth.find_keys(identifier)

    assert result == out
