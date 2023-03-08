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
    from pass_collaborate.model.auth import AuthStore
    from pass_collaborate.model.pass_ import PassStore


def test_group_add(
    cli_runner: CliRunner,
    pass_: "PassStore",
    admin: "User",
    developer: "User",
    attacker: "User",
) -> None:
    """
    Given: A configured environment
    When: calling group add command with an email, a user name and a key id
    Then: A group is added and the data stored in the auth store are the emails
    """
    pass_.auth.add_user(developer.name, developer.key, developer.email)
    pass_.auth.add_user(attacker.name, attacker.key, attacker.email)

    result = cli_runner.invoke(
        app, ["group", "add", "test_group", developer.email, admin.name, attacker.key]
    )

    assert result.exit_code == 0
    pass_.auth.reload()
    saved_group, _ = pass_.auth.get_group("test_group")
    assert saved_group == Group(
        name="test_group", users=[developer.email, admin.email, attacker.email]
    )


def test_group_list(cli_runner: CliRunner, auth: "AuthStore") -> None:
    """
    Given: A configured environment and a group added
    When: calling group list command
    Then: The groups are listed
    """
    auth.add_group("test_group")

    result = cli_runner.invoke(app, ["group", "list"])

    assert result.exit_code == 0
    assert "test_group" in result.stdout


@pytest.mark.parametrize(
    "group",
    [
        GroupFactory.build(users=[]),
        GroupFactory.build(users=["developer@example.org"]),
        GroupFactory.build(users=["developer@example.org", "admin@example.org"]),
    ],
)
def test_group_show(
    cli_runner: CliRunner,
    pass_: "PassStore",
    developer: "User",
    admin: "User",
    group: Group,
) -> None:
    """
    Given: A configured environment and a group added
    When: calling group show command
    Then: The group information is shown
    """
    pass_.auth.add_user(developer.name, developer.key, developer.email)
    pass_.auth.add_group(name=group.name, user_ids=group.users)  # type: ignore

    result = cli_runner.invoke(app, ["group", "show", group.name])

    assert result.exit_code == 0
    assert re.search(rf"{group.name}", result.stdout)
    assert group.users is not None
    if len(group.users) > 0:
        assert re.search(
            rf".*{developer.name}: {developer.email} \({developer.key}\).*",
            result.stdout,
        )
    if len(group.users) > 1:
        assert re.search(
            rf".*{admin.name}: {admin.email} \({admin.key}\).*", result.stdout
        )


@pytest.mark.parametrize(
    "entity",
    [
        "developers",
        "developer@example.org",
        "developer",
        "8DFE8782CD025ED6220D305115575911602DDD94",
    ],
)
def test_group_authorize_a_directory(
    cli_runner: CliRunner,
    pass_: "PassStore",
    pass_dev: "PassStore",
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
    pass_.auth.add_user(name=developer.name, email=developer.email, key=developer.key)
    pass_.auth.add_group(name="developers", user_ids=["developer@example.org"])
    # Check that the permissions are right
    for element in ["web", "database", "bastion"]:
        assert pass_.has_access(element)
        assert not pass_.has_access(element, identifier=developer.email)
    for environment in ("production", "staging"):
        assert pass_.can_decrypt(pass_.path(f"web/{environment}"))
        assert not pass_dev.can_decrypt(pass_.path(f"web/{environment}"))

    result = cli_runner.invoke(app, ["group", "authorize", entity, "web"])

    assert result.exit_code == 0
    pass_.auth.reload()
    assert pass_.has_access("web", identifier=developer.email)
    for environment in ("production", "staging"):
        assert pass_.can_decrypt(pass_.path(f"web/{environment}"))
        assert pass_dev.can_decrypt(pass_.path(f"web/{environment}"))
    # Check that the permissions of the rest of the store have not changed.
    assert pass_.has_access("web")
    for element in ["database", "bastion"]:
        assert pass_.has_access(element)
        assert not pass_.has_access(element, identifier=developer.email)
    assert "8DFE8782CD025ED6220D305115575911602DDD94" in gpg_id.read_text(
        encoding="utf-8"
    )


def test_group_authorize_cant_authorize_file(cli_runner: CliRunner) -> None:
    """
    Given: A configured environment
    When: Trying to authorize a file
    Then: An error is raised as we don't yet support giving granular
        permissions to files.
    """
    result = cli_runner.invoke(app, ["group", "authorize", "user", "bastion"])

    assert result.exit_code == 2
    assert "Changing access to a file is not yet supported" in result.stderr


def test_group_authorize_is_idempotent(
    cli_runner: CliRunner, pass_: "PassStore", admin: "User"
) -> None:
    """
    Given: A configured environment
    When: Trying to authorize a directory that is already authorized
    Then: It doesn't do anything as it's already authorized.
    """
    pass_.auth.add_group(name="admins", user_ids=[admin.email])
    pass_.change_access("web", ["admins"])
    assert pass_.auth.access["web/.gpg-id"] == ["admins"]

    result = cli_runner.invoke(app, ["group", "authorize", "admins", "web"])

    assert result.exit_code == 0
    pass_.auth.reload()
    assert pass_.auth.access["web/.gpg-id"] == ["admins"]


def test_group_authorize_can_ignore_parent(
    cli_runner: CliRunner, pass_: "PassStore", admin: "User", developer: "User"
) -> None:
    """
    Given: A configured environment
    When: Authorize a directory with the --ignore_parent flag
    Then: It ignores the permissions of the parent .gpg-id file
        and sets only the new one
    """
    pass_.auth.add_user(name=developer.name, email=developer.email, key=developer.key)
    pass_.auth.add_group(name="developers", user_ids=[developer.email])
    assert pass_.has_access("web", admin.name)
    assert not pass_.has_access("web", "developers")

    result = cli_runner.invoke(
        app, ["group", "authorize", "--ignore-parent", "developers", "web"]
    )

    assert result.exit_code == 0
    pass_.auth.reload()
    assert not pass_.has_access("web", admin.name)
    assert pass_.has_access("web", "developers")


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
    cli_runner: CliRunner,
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

    result = cli_runner.invoke(app, arguments)

    assert result.exit_code == 0
    auth.reload()
    saved_group, saved_users = auth.get_group("test_group")
    assert saved_group.users is not None
    if "developer@example.org" in arguments:
        assert developer in saved_users
    if "admin@example.org" in arguments:
        assert admin in saved_users


def test_group_with_associated_passwords_add_users(
    cli_runner: CliRunner,
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
    pass_.auth.add_user(name=developer.name, email=developer.email, key=developer.key)
    pass_.auth.add_group(name="developers", user_ids=[admin.email])
    pass_.change_access(add_identifiers=["developers"], pass_dir_path="web")
    for environment in ("production", "staging"):
        assert pass_.can_decrypt(pass_.path(f"web/{environment}"))
        assert not pass_dev.can_decrypt(pass_.path(f"web/{environment}"))

    result = cli_runner.invoke(
        app, ["group", "add-users", developer.email, "developers"], env={}
    )

    assert result.exit_code == 0
    for environment in ("production", "staging"):
        assert pass_.can_decrypt(pass_.path(f"web/{environment}"))
        assert pass_dev.can_decrypt(pass_.path(f"web/{environment}"))


def test_group_remove_user_from_group(
    cli_runner: CliRunner,
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
    pass_.auth.add_user(name=developer.name, email=developer.email, key=developer.key)
    pass_.auth.add_group(name="developers", user_ids=[admin.email, developer.email])
    pass_.change_access(add_identifiers=["developers"], pass_dir_path="web")
    for environment in ("production", "staging"):
        assert pass_.can_decrypt(pass_.path(f"web/{environment}"))
        assert pass_dev.can_decrypt(pass_.path(f"web/{environment}"))

    result = cli_runner.invoke(
        app, ["group", "remove-users", developer.email, "developers"]
    )

    assert result.exit_code == 0
    for environment in ("production", "staging"):
        assert pass_.can_decrypt(pass_.path(f"web/{environment}"))
        assert not pass_dev.can_decrypt(pass_.path(f"web/{environment}"))


def test_group_remove_user_that_is_not_part_of_group(
    cli_runner: CliRunner,
    developer: User,
    pass_: "PassStore",
    caplog: LogCaptureFixture,
) -> None:
    """
    Given: A group without any user
    When: Removing a user that is not part of the group
    Then: A warning is raised but the program exits fine
    """
    caplog.set_level(logging.INFO)
    pass_.auth.add_user(name=developer.name, email=developer.email, key=developer.key)
    pass_.auth.add_group(name="developers", user_ids=[])

    result = cli_runner.invoke(
        app, ["group", "remove-users", developer.email, "developers"]
    )

    assert result.exit_code == 0
    assert (
        "pass_collaborate.model.auth",
        logging.INFO,
        f"User {developer.name} is not part of the developers group",
    ) in caplog.record_tuples
