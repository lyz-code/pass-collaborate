"""Test the implementation of the group command line command."""

import re
from typing import TYPE_CHECKING, List

import pytest
from typer.testing import CliRunner

from pass_collaborate.adapters import PassStore
from pass_collaborate.entrypoints.cli import app
from pass_collaborate.model import Group, User
from pass_collaborate.services import has_access

from ..factories import GroupFactory

if TYPE_CHECKING:
    from pass_collaborate.adapters import AuthStore


def test_group_add(runner: CliRunner, auth: "AuthStore") -> None:
    """
    Given: A configured environment
    When: calling group add command
    Then: A group is added
    """
    result = runner.invoke(
        app, ["group", "add", "test_group", "user@example.org", "admin@example.org"]
    )

    assert result.exit_code == 0
    auth.reload()
    saved_group = auth.get_group("test_group")
    assert saved_group == Group(
        name="test_group", users=["user@example.org", "admin@example.org"]
    )


def test_group_list(runner: CliRunner, auth: "AuthStore") -> None:
    """
    Given: A configured environment and a group added
    When: calling group list command
    Then: The groups are listed
    """
    auth.add_group("test_group")

    result = runner.invoke(app, ["group", "list"])

    assert result.exit_code == 0
    assert "test_group" in result.stdout


@pytest.mark.parametrize(
    "group",
    [
        GroupFactory.build(users=[]),
        GroupFactory.build(users=["user@example.org"]),
        GroupFactory.build(users=["user@example.org", "admin@example.org"]),
    ],
)
def test_group_show(runner: CliRunner, auth: "AuthStore", group: Group) -> None:
    """
    Given: A configured environment and a group added
    When: calling group show command
    Then: The group information is shown
    """
    auth.add_group(name=group.name, users=group.users)

    result = runner.invoke(app, ["group", "show", group.name])

    assert result.exit_code == 0
    assert re.search(rf"Name *{group.name}", result.stdout)
    assert group.users is not None
    if len(group.users) > 0:
        assert re.search(rf"Users *- {group.users[0]}", result.stdout)
        for user in group.users[1:]:
            assert f"- {user}" in result.stdout


@pytest.mark.parametrize(
    "arguments",
    [
        ["group", "add-users", "user@example.org", "test_group"],
        ["group", "add-users", "user@example.org", "admin@example.org", "test_group"],
    ],
)
def test_group_add_users(
    runner: CliRunner, auth: "AuthStore", arguments: List[str]
) -> None:
    """
    Given: A configured environment and an empty group
    When: adding users to a group
    Then: users are added
    """
    auth.add_group("test_group")

    result = runner.invoke(app, arguments)

    assert result.exit_code == 0
    auth.reload()
    saved_group = auth.get_group("test_group")
    assert saved_group.users is not None
    for user in [argument for argument in arguments if "@" in argument]:
        assert user in saved_group.users


@pytest.mark.parametrize(
    "entity",
    [
        "developers",
        "developer@example.org",
        "Marie",
        "8DFE8782CD025ED6220D305115575911602DDD94",
    ],
)
def test_group_authorize(
    runner: CliRunner,
    auth: "AuthStore",
    pass_dev: "PassStore",
    pass_: "PassStore",
    entity: str,
    developer: User,
) -> None:
    """
    Given: A configured environment and a group added
    When: calling group authorize command on a subdirectory either with a group name
        or a user identifier.
    Then: The group members are authorized to access the data.
    """
    auth.add_user(name=developer.name, email=developer.email, key=developer.key)
    auth.add_group(name="developers", users=["developer@example.org"])
    # Check that the permissions are reight
    for element in ["web", "database", "bastion"]:
        assert has_access(auth, pass_, element)
        assert not has_access(auth, pass_dev, element)

    result = runner.invoke(app, ["group", "authorize", entity, "web"])

    assert result.exit_code == 0
    auth.reload()
    assert has_access(auth, pass_dev, "web")
    # Check that the permissions of the rest of the store have not changed.
    assert has_access(auth, pass_, "web")
    for element in ["database", "bastion"]:
        assert has_access(auth, pass_, element)
        assert not has_access(auth, pass_dev, element)
