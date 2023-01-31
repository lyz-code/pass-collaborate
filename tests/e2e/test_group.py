"""Test the implementation of the group command line command."""

import re
from typing import TYPE_CHECKING, List
from pathlib import Path

import pytest
from typer.testing import CliRunner

from pass_collaborate.entrypoints.cli import app
from pass_collaborate.model.auth import Group, User

from ..factories import GroupFactory

if TYPE_CHECKING:
    from pass_collaborate.model.pass_ import PassStore


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
def test_group_authorize_a_directory(
    runner: CliRunner,
    pass_: 'PassStore',
    pass_dev: 'PassStore',
    auth: 'AuthStore',
    entity: str,
    developer: User,
) -> None:
    """
    Given: A configured environment and a group added. With no `.gpg-id` file in the directory we want to change the permissions.
    When: calling group authorize command on a subdirectory either with a group name
        or a user identifier.
    Then: The group members are authorized to access the data and the .gpg-id file of the directory contains the new key.
    """
    gpg_id = Path(pass_.store_dir / 'web' / '.gpg-id')
    assert not gpg_id.is_file()
    auth.add_user(name=developer.name, email=developer.email, key=developer.key)
    auth.add_group(name="developers", users=["developer@example.org"])
    # Check that the permissions are right
    for element in ["web", "database", "bastion"]:
        assert pass_.has_access(element)
        assert not pass_dev.has_access(element)
    for environment in ('production', 'staging'):
        assert pass_.can_decrypt(pass_.path(f'web/{environment}'))
        assert not pass_dev.can_decrypt(pass_.path(f'web/{environment}'))

    result = runner.invoke(app, ["group", "authorize", entity, "web"])

    assert result.exit_code == 0
    auth.reload()
    assert pass_dev.has_access("web")
    for environment in ('production', 'staging'):
        assert pass_.can_decrypt(pass_.path(f'web/{environment}'))
        assert pass_dev.can_decrypt(pass_.path(f'web/{environment}'))
    # Check that the permissions of the rest of the store have not changed.
    assert pass_.has_access("web")
    for element in ["database", "bastion"]:
        assert pass_.has_access(element)
        assert not pass_dev.has_access(element)
    assert '8DFE8782CD025ED6220D305115575911602DDD94' in gpg_id.read_text()


def test_group_authorize_cant_authorize_file(runner: CliRunner) -> None:
    """
    Given: A configured environment
    When: Trying to authorize a file
    Then: An error is raised as we don't yet support giving granular permissions to files.
    """
    runner.mix_stderr = False
    result = runner.invoke(app, ["group", "authorize", 'user', "bastion"])

    assert result.exit_code == 2
    assert 'Authorizing access to a file is not yet supported' in result.stderr


def test_group_authorize_cant_authorize_id_that_matches_two_elements(
    runner: CliRunner, 
    auth: 'AuthStore',
    developer: User,
    attacker: User,
) -> None:
    """
    Given: A configured environment with two users with the same name
    When: Trying to authorize a directory with the email which is shared by two users
    Then: An error is raised as we don't know which user has to be authorized
    """
    runner.mix_stderr = False
    auth.add_user(name=developer.name, email=developer.email, key=developer.key)
    auth.add_user(name=attacker.name, email=developer.email, key=attacker.key)
    result = runner.invoke(app, ["group", "authorize", developer.email, "web"])

    assert result.exit_code == 401
    assert 'More than one user matched the selected criteria' in result.stderr


@pytest.mark.skip("Not yet}")
def test_group_authorize_asks_for_confirmation_by_default() -> None:
    """
    Given:
    When:
    Then:
    """
    result = False

    assert result
