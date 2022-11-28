"""Test the implementation of the AuthStore."""

from typing import TYPE_CHECKING

import pytest

from pass_collaborate.exceptions import NotFoundError
from pass_collaborate.model import Group

from ...factories import UserFactory

if TYPE_CHECKING:
    from pass_collaborate.adapters import AuthStore


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


@pytest.mark.parametrize("identifier", [])
def test_get_user_happy_path() -> None:
    """
    Given:
    When: getting by the email, key or name
    Then: the user is returned
    """
    result = False

    assert result


@pytest.mark.skip("Not yet}")
def test_get_user_raises_exception_if_more_than_one() -> None:
    """
    Given:
    When:
    Then:
    """
    result = False

    assert result
