"""Test the implementation of the group command line command."""

import logging
import re
from pathlib import Path
from typing import TYPE_CHECKING, List

import pytest
from _pytest.logging import LogCaptureFixture
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
    pass_: "PassStore",
    pass_dev: "PassStore",
    auth: "AuthStore",
    entity: str,
    developer: User,
) -> None:
    """
    Given: A configured environment and a group added. With no `.gpg-id` file
        in the directory we want to change the permissions.
    When: calling group authorize command on a subdirectory either with a group
        name or a user identifier.
    Then: The group members are authorized to access the data and the .gpg-id
        file of the directory contains the new key.
    """
    gpg_id = Path(pass_.store_dir / "web" / ".gpg-id")
    assert not gpg_id.is_file()
    auth.add_user(name=developer.name, email=developer.email, key=developer.key)
    auth.add_group(name="developers", users=["developer@example.org"])
    # Check that the permissions are right
    for element in ["web", "database", "bastion"]:
        assert pass_.has_access(element)
        assert not pass_dev.has_access(element)
    for environment in ("production", "staging"):
        assert pass_.can_decrypt(pass_.path(f"web/{environment}"))
        assert not pass_dev.can_decrypt(pass_.path(f"web/{environment}"))

    result = runner.invoke(app, ["group", "authorize", entity, "web"])

    assert result.exit_code == 0
    auth.reload()
    assert pass_dev.has_access("web")
    for environment in ("production", "staging"):
        assert pass_.can_decrypt(pass_.path(f"web/{environment}"))
        assert pass_dev.can_decrypt(pass_.path(f"web/{environment}"))
    # Check that the permissions of the rest of the store have not changed.
    assert pass_.has_access("web")
    for element in ["database", "bastion"]:
        assert pass_.has_access(element)
        assert not pass_dev.has_access(element)
    assert "8DFE8782CD025ED6220D305115575911602DDD94" in gpg_id.read_text()


def test_group_authorize_cant_authorize_file(runner: CliRunner) -> None:
    """
    Given: A configured environment
    When: Trying to authorize a file
    Then: An error is raised as we don't yet support giving granular
        permissions to files.
    """
    runner.mix_stderr = False

    result = runner.invoke(app, ["group", "authorize", "user", "bastion"])

    assert result.exit_code == 2
    assert "Authorizing access to a file is not yet supported" in result.stderr


def test_group_authorize_cant_authorize_id_that_matches_two_elements(
    runner: CliRunner,
    auth: "AuthStore",
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
    assert "More than one user matched the selected criteria" in result.stderr


@pytest.mark.skip("Not yet}")
def test_group_authorize_asks_for_confirmation_by_default() -> None:
    """
    Given:
    When:
    Then:
    """
    result = False

    assert result


@pytest.mark.parametrize(
    "arguments",
    [
        ["group", "add-users", "developer@example.org", "test_group"],
        [
            "group",
            "add-users",
            "developer@example.org",
            "admin@example.org",
            "test_group",
        ],
    ],
)
def test_group_add_users(
    runner: CliRunner,
    auth: "AuthStore",
    arguments: List[str],
    developer: User,
    admin: User,
) -> None:
    """
    Given: A configured environment and an empty group
    When: adding users to a group
    Then: users are added
    """
    auth.add_user(name=admin.name, email=admin.email, key=admin.key)
    auth.add_user(name=developer.name, email=developer.email, key=developer.key)
    auth.add_group("test_group")

    result = runner.invoke(app, arguments)

    assert result.exit_code == 0
    auth.reload()
    saved_group = auth.get_group("test_group")
    assert saved_group.users is not None
    if "developer@example.org" in arguments:
        assert "Marie" in saved_group.users
    if "admin@example.org" in arguments:
        assert "Admin" in saved_group.users


def test_group_with_associated_passwords_add_users(
    runner: CliRunner,
    auth: "AuthStore",
    pass_: "PassStore",
    pass_dev: "PassStore",
    developer: User,
    admin: User,
) -> None:
    """
    Given: A configured environment and a group authorized to some passwords
    When: adding users to a group
    Then: the new users are able to read the group passwords
    """
    auth.add_user(name=admin.name, email=admin.email, key=admin.key)
    auth.add_user(name=developer.name, email=developer.email, key=developer.key)
    auth.add_group(name="developers", users=[admin.email])
    pass_.authorize(id_="developers", pass_dir_path="web")
    for environment in ("production", "staging"):
        assert pass_.can_decrypt(pass_.path(f"web/{environment}"))
        assert not pass_dev.can_decrypt(pass_.path(f"web/{environment}"))

    result = runner.invoke(app, ["group", "add-users", developer.email, "developers"])

    assert result.exit_code == 0
    for environment in ("production", "staging"):
        assert pass_.can_decrypt(pass_.path(f"web/{environment}"))
        assert pass_dev.can_decrypt(pass_.path(f"web/{environment}"))


def test_group_remove_user_from_group(
    runner: CliRunner,
    auth: "AuthStore",
    pass_: "PassStore",
    pass_dev: "PassStore",
    developer: User,
    admin: User,
) -> None:
    """
    Given: A configured environment and a group authorized to some passwords
    When: removing a user from the group
    Then: the removed user are not able to read the group passwords
    """
    auth.add_user(name=admin.name, email=admin.email, key=admin.key)
    auth.add_user(name=developer.name, email=developer.email, key=developer.key)
    auth.add_group(name="developers", users=[admin.email, developer.email])
    pass_.auth.reload()
    pass_.authorize(id_="developers", pass_dir_path="web")
    for environment in ("production", "staging"):
        assert pass_.can_decrypt(pass_.path(f"web/{environment}"))
        assert pass_dev.can_decrypt(pass_.path(f"web/{environment}"))

    result = runner.invoke(
        app, ["group", "remove-users", developer.email, "developers"]
    )

    assert result.exit_code == 0
    for environment in ("production", "staging"):
        assert pass_.can_decrypt(pass_.path(f"web/{environment}"))
        assert not pass_dev.can_decrypt(pass_.path(f"web/{environment}"))


def test_group_remove_user_that_is_not_part_of_group(
    runner: CliRunner,
    developer: User,
    pass_: "PassStore",
    auth: "AuthStore",
    caplog: LogCaptureFixture,
) -> None:
    """
    Given: A group without any user
    When: Removing a user that is not part of the group
    Then: A warning is raised but the program exits fine
    """
    caplog.set_level(logging.INFO)
    auth.add_user(name=developer.name, email=developer.email, key=developer.key)
    auth.add_group(name="developers", users=[])
    pass_.auth.reload()

    result = runner.invoke(
        app, ["group", "remove-users", developer.email, "developers"]
    )

    assert result.exit_code == 0
    assert (
        "pass_collaborate.model.auth",
        logging.INFO,
        f"User {developer.name} is not part of the developers group",
    ) in caplog.record_tuples
