"""Test the implementation of the AuthStore."""

from typing import TYPE_CHECKING, List

import pytest

from pass_collaborate.exceptions import NotFoundError
from pass_collaborate.model.auth import Group, User

from ...factories import GroupFactory, UserFactory

if TYPE_CHECKING:
    from pass_collaborate.model.auth import AuthStore
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
    with pytest.raises(
        NotFoundError, match="There is no group that matches fight_club."
    ):
        auth.get_group("fight_club")


def test_raises_exception_if_user_exists(auth: "AuthStore") -> None:
    """
    Given: an auth store
    When: creating a user that already exists
    Then: an exception is raised.
    """
    user = UserFactory.build()
    auth.add_user(user.name, user.key, user.email)

    with pytest.raises(
        ValueError, match=f"The user {user.name} is using the name {user.name}."
    ):
        auth.add_user(user.name, user.key, user.email)


def test_raises_exception_if_a_user_with_same_email_exists(auth: "AuthStore") -> None:
    """
    Given: an auth store
    When: creating a user using an email that is already selected for other user
    Then: an exception is raised.
    """
    user = UserFactory.build()
    user2 = UserFactory.build(email=user.email)
    auth.add_user(user.name, user.key, user.email)

    with pytest.raises(
        ValueError, match=f"The user {user.name} is using the email {user.email}."
    ):
        auth.add_user(user2.name, user2.key, user2.email)


@pytest.mark.parametrize(
    "identifier",
    [
        "developer",
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
    ("identifier", "out"),
    [
        ("developer", ["8DFE8782CD025ED6220D305115575911602DDD94"]),
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
    auth.add_group(name="developers", user_ids=["developer@example.org"])

    result = auth.find_keys(identifier)

    assert result == out


def test_group_remove_users_work_on_non_existent_user() -> None:
    """
    Given: A configured group
    When: Trying to remove a user that is not part of the group
    Then: The command doesn't remove anything but it doesn't raise an exception either
    """
    group = GroupFactory.build()
    user = UserFactory.build()

    result = group.remove_users(users=[user])

    assert result is False


def test_group_add_users_is_idempotent() -> None:
    """
    Given: A configured group
    When: Adding a user that it's already in the store
    Then: The user is not added again
    """
    user = UserFactory.build()
    group = GroupFactory.build(users=[])
    group.add_users([user])

    result = group.add_users([user])

    assert group.users == [user.email]
    assert result is False


def test_user_can_have_accents_on_name() -> None:
    """
    Given: the model of the user
    When: Adding a user with accents in the name
    Then: The user is added well
    """
    user = UserFactory.build(name="Péter")

    result = User(name=user.name, email=user.email, key=user.key)

    assert user == result


def test_auth_loads_gpg_id_even_if_entry_exists(
    auth: "AuthStore", admin: "User"
) -> None:
    """
    Given: an auth store with a key in the access property
    Then: The missing keys are loaded
    """
    auth.access[".gpg-id"] = []
    auth.save()

    auth.reload()  # act

    assert auth.access[".gpg-id"] == [admin.key]
