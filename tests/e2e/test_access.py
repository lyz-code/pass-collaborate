"""Test the implementation of the access command line command."""

from textwrap import dedent
from typing import TYPE_CHECKING

import pytest
from typer.testing import CliRunner

from pass_collaborate.entrypoints.cli import app

if TYPE_CHECKING:
    from pass_collaborate.model.auth import User
    from pass_collaborate.model.pass_ import PassStore


@pytest.mark.parametrize(
    "identifier",
    [
        "developers",
        "developer@example.org",
        "developer",
        "8DFE8782CD025ED6220D305115575911602DDD94",
    ],
)
def test_access_happy_path(
    runner: CliRunner,
    pass_: "PassStore",
    developer: "User",
    identifier: str,
) -> None:
    """
    Given: A user belonging to a group that has access to some passwords
    When: calling access command line
    Then: A tree is shown with only the elements it has access to
    """
    pass_.auth.add_user(name=developer.name, email=developer.email, key=developer.key)
    pass_.auth.add_group(name="developers", users=[developer.email])
    pass_.change_access(add_identifiers=["developers"], pass_dir_path="web")

    result = runner.invoke(app, ["access", identifier])

    assert result.exit_code == 0
    expected_output = dedent(
        f"""\
        Password access for {identifier}
        └── web
            ├── staging
            └── production
        """
    )
    assert result.stdout == expected_output
