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
    cli_runner: CliRunner,
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
    pass_.auth.add_group(name="developers", user_ids=[developer.email])
    pass_.change_access(add_identifiers=["developers"], pass_dir_path="web")

    result = cli_runner.invoke(app, ["access", identifier])

    assert result.exit_code == 0
    expected_output = dedent(
        f"""\
        Password access for {identifier}
        └── web
            ├── production
            └── staging
        """
    )
    assert result.stdout == expected_output


def test_access_with_no_groups(
    cli_runner: CliRunner,
    pass_: "PassStore",
    admin: "User",
) -> None:
    """
    Given: An auth store without groups
    When: calling access command line with the admin
    Then: A tree is shown with the elements it has access to
    """
    result = cli_runner.invoke(app, ["access", admin.email])

    assert result.exit_code == 0
    expected_output = dedent(
        f"""\
        Password access for {admin.email}
        ├── bastion
        ├── database
        │   ├── production
        │   └── staging
        └── web
            ├── production
            └── staging
        """
    )
    assert result.stdout == expected_output


@pytest.mark.skip("Not yet")
def test_access_doesnt_analyze_the_files_by_default(
    cli_runner: CliRunner,
    pass_: "PassStore",
    attacker: "User",
    admin: "User",
) -> None:
    """
    Given: An auth store with a file that is encrypted with an attacker's key
        but that's not shown in the .gpg-id file
    When: calling access command line with the attacker id with the deep flag
    Then: The element is not shown as by default it doesn't analyze the files content.

    For the sake of speed.
    """
    pass_.key.encrypt(pass_.store_dir / "bastion.gpg", [admin.key, attacker.key])

    result = cli_runner.invoke(app, ["access", attacker.email])

    assert result.exit_code == 0
    assert "bastion" not in result.stdout


@pytest.mark.skip("Not yet")
def test_access_deep_analyzes_the_files(
    cli_runner: CliRunner,
    pass_: "PassStore",
    attacker: "User",
    admin: "User",
) -> None:
    """
    Given: An auth store with a file that is encrypted with an attacker's key
        but that's not shown in the .gpg-id file
    When: calling access command line with the attacker id with the deep flag
    Then: A tree is shown with the element it has access to
    """
    pass_.key.encrypt(pass_.store_dir / "bastion.gpg", [admin.key, attacker.key])

    result = cli_runner.invoke(app, ["access", "--deep", attacker.email])

    assert result.exit_code == 0
    expected_output = dedent(
        f"""\
        Password access for {attacker.email}
        └── bastion
        """
    )
    assert result.stdout == expected_output
