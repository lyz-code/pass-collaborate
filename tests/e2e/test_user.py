"""Test the implementation of the user command line command."""

import re
from typing import TYPE_CHECKING

import pytest
from typer.testing import CliRunner

from pass_collaborate.entrypoints.cli import app

from ..factories import UserFactory

if TYPE_CHECKING:
    from pass_collaborate.model.auth import AuthStore, User


def test_user_add(runner: CliRunner, auth: "AuthStore", developer: "User") -> None:
    """
    Given: A configured environment
    When: calling user add command
    Then: A user is added
    """
    result = runner.invoke(app, ["user", "add", developer.email])

    assert result.exit_code == 0
    auth.reload()
    saved_user = auth.get_user(developer.key)
    assert developer == saved_user


def test_user_add_can_overwrite_name(
    runner: CliRunner, auth: "AuthStore", developer: "User"
) -> None:
    """
    Given: A configured environment
    When: calling user add command with the --name attribute
    Then: A user is added
    """
    result = runner.invoke(app, ["user", "add", developer.email, "--name", "Marie"])

    assert result.exit_code == 0
    auth.reload()
    saved_user = auth.get_user(developer.key)
    assert saved_user.name == "Marie"


def test_user_add_can_overwrite_email(
    runner: CliRunner, auth: "AuthStore", developer: "User"
) -> None:
    """
    Given: A configured environment
    When: calling user add command with the --email attribute
    Then: A user is added
    """
    result = runner.invoke(
        app, ["user", "add", developer.key, "--email", "other@test.org"]
    )

    assert result.exit_code == 0
    auth.reload()
    saved_user = auth.get_user(developer.key)
    assert saved_user.email == "other@test.org"


def test_user_add_fails_if_gpg_key_not_imported(
    runner: CliRunner, developer: "User"
) -> None:
    """
    Given: a gpg store that doesn't have the gpg key of the user we want to
        import
    When: calling user add command
    Then: An error is returned
    """
    runner.mix_stderr = False
    user = UserFactory.build()

    result = runner.invoke(app, ["user", "add", user.key])

    assert result.exit_code == 404
    assert f"No key found for {user.key}" in result.stderr


@pytest.mark.skip("Not yet}")
def test_user_add_works_if_gpg_key_not_imported_but_in_available_keys(
    runner: CliRunner, developer: "User"
) -> None:
    """
    Given: a gpg store that doesn't have the gpg key of the user we want to
        import but the public key is stored in the .gpg-pub-keys directory
    When: calling user add command
    Then: the public key is imported and the user is added well.
    """
    result = False

    assert result


@pytest.mark.skip("Not yet}")
def test_user_add_saves_public_key_in_the_public_key_store(
    runner: CliRunner, developer: "User"
) -> None:
    """
    Given: a gpg store that has the gpg key of the user we want to import but
        the public key storage doesn't
    When: calling user add command
    Then: the public key is added to the storage.
    """
    result = False

    assert result


def test_user_list(runner: CliRunner) -> None:
    """
    Given: A configured environment
    When: calling user list command
    Then: The users are listed
    """
    result = runner.invoke(app, ["user", "list"])

    assert result.exit_code == 0
    assert "admin" in result.stdout


def test_user_show(runner: CliRunner, admin: "User") -> None:
    """
    Given: A configured environment
    When: calling user show command
    Then: The user information is shown
    """
    result = runner.invoke(app, ["user", "show", admin.name])

    assert result.exit_code == 0
    for regexp in [
        rf"Name *{admin.name}",
        rf"Email *{admin.email}",
        rf"Key *{admin.key}",
    ]:
        assert re.search(regexp, result.stdout)
