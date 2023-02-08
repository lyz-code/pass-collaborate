"""Test the implementation of the user command line command."""

from typing import TYPE_CHECKING

import pytest
from typer.testing import CliRunner

from pass_collaborate.entrypoints.cli import app

from ..factories import UserFactory

if TYPE_CHECKING:
    from pass_collaborate.adapters import AuthStore
    from pass_collaborate.model.auth import User

def test_user_add(runner: CliRunner, auth: "AuthStore") -> None:
    """
    Given: A configured environment
    When: calling user add command
    Then: A user is added
    """
    user = UserFactory.build()

    result = runner.invoke(app, ["user", "add", user.name, user.key, user.email])

    assert result.exit_code == 0
    auth.reload()
    saved_user = auth.get_user(user.key)
    assert user == saved_user


@pytest.mark.skip("Not yet}")
def test_user_add_fails_if_gpg_key_not_imported(
    runner: CliRunner, developer: "User"
) -> None:
    """
    Given: a gpg store that doesn't have the gpg key of the user we want to import
    When: calling user add command
    Then: An error is returned
    """
    result = False

    assert result


@pytest.mark.skip("Not yet}")
def test_user_add_works_if_gpg_key_not_imported_but_in_available_keys(
    runner: CliRunner, developer: "User"
) -> None:
    """
    Given: a gpg store that doesn't have the gpg key of the user we want to import but the public key is stored in the .gpg-pub-keys directory
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
    Given: a gpg store that has the gpg key of the user we want to import but the public key storage doesn't
    When: calling user add command
    Then: the public key is added to the storage.
    """
    result = False

    assert result
