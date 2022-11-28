"""Test the implementation of the user command line command."""

from typing import TYPE_CHECKING

from typer.testing import CliRunner

from pass_collaborate.entrypoints.cli import app

from ..factories import UserFactory

if TYPE_CHECKING:
    from pass_collaborate.adapters import AuthStore


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
