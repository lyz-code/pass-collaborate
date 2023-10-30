"""Test the command line interface."""

import logging
import os
import re
from datetime import datetime
from typing import TYPE_CHECKING, Dict, List

import pytest
from _pytest.logging import LogCaptureFixture
from typer.testing import CliRunner

from pass_collaborate.entrypoints.cli import app
from pass_collaborate.version import __version__

from ..factories import UserFactory

if TYPE_CHECKING:
    from pass_collaborate.model.auth import User
    from pass_collaborate.model.pass_ import PassStore


log = logging.getLogger(__name__)


def test_version(cli_runner: CliRunner) -> None:
    """Prints program version when called with --version."""
    result = cli_runner.invoke(app, ["--version"])

    assert result.exit_code == 0
    assert re.search(
        rf" *pass_collaborate: {__version__}\n *Python: .*\n *Platform: .*",
        result.stdout,
    )


def test_generates_default_auth_conf_if_none_is_available(
    cli_runner: CliRunner, pass_: "PassStore", admin: "User"
) -> None:
    """
    Given: An environment without an auth config file.
    When: calling an auth related command.
    Then: The config file is created with the template and the users are created from
        The key store.
    """
    os.remove(pass_.auth.config_file)

    result = cli_runner.invoke(app, ["group", "add", "test_group"])

    assert result.exit_code == 0
    assert os.path.exists(pass_.auth.config_file)
    pass_.auth.reload()
    assert pass_.auth.users == [admin]


def test_pass_returns_error_when_no_keys_are_found(
    cli_runner: CliRunner, pass_: "PassStore", caplog: LogCaptureFixture
) -> None:
    """
    Given: A password store that uses a GPG key that is not on our keystore
    When: calling any pass_collaborate command
    Then: An error is returned
    """
    user = UserFactory.build()
    gpg_id = pass_.store_dir / ".gpg-id"
    gpg_id.write_text(f"{user.key}\n")

    result = cli_runner.invoke(app, ["access", user.name])

    assert result.exit_code == 404
    assert (
        f"Please import the next gpg keys in your gpg keystore:\n{user.key}"
        in result.stderr
    )


@pytest.mark.parametrize(
    ("args", "env"),
    [
        (["--auth-dir", "web", "group", "add", "test_group"], {}),
        (["group", "add", "test_group"], {"PASSWORD_AUTH_DIR": "web"}),
    ],
)
def test_supports_auth_file_not_in_root_of_pass(
    cli_runner: CliRunner,
    pass_: "PassStore",
    admin: "User",
    developer: "User",
    args: List[str],
    env: Dict[str, str],
) -> None:
    """
    Given: An environment with an auth config file in a subdirectory of
        `~/.passwordstore`.
    When: calling an auth related command either with the environment variable
        or the flag to set the alternative auth store.
    Then: The config file is created with the template and the users are
        created from The key store.

        The users from the root of the password store are not loaded though,
        only the ones on the children of the specified auth-dir.
    """
    os.remove(pass_.auth.config_file)
    new_auth_store = pass_.auth.store_dir / "web"
    new_config = new_auth_store / ".auth.yaml"
    new_gpg_id = new_auth_store / ".gpg-id"
    new_gpg_id.write_text(f"{developer.key}\n")
    assert not new_config.exists()

    result = cli_runner.invoke(app, args, env=env)

    assert result.exit_code == 0
    assert not os.path.exists(pass_.auth.config_file)
    assert new_config.exists()
    pass_.auth.load(str(new_config))
    assert pass_.auth.users == [developer]
    assert pass_.auth.groups[0].name == "test_group"


def test_reencrypt_all_password_store(
    cli_runner: CliRunner, pass_: "PassStore", admin: "User"
) -> None:
    r"""
    Given: A pass store with a .gpg-id file that does not end in \n
    When: Using the reencrypt method
    Then: all of the files are rencrypted, to check this we make sure that:
        - The .gpg-id file has the \n fixed.
        - The modified time of a gpg file is recent.
    """
    gpg_id_file = pass_.store_dir / ".gpg-id"
    gpg_id_file.write_text(admin.key)
    assert gpg_id_file.read_text()[-1] != "\n"
    assert datetime.now().timestamp() - pass_.path("bastion").stat().st_mtime > 60

    cli_runner.invoke(app, ["reencrypt"])  # act

    assert gpg_id_file.read_text()[-1] == "\n"
    assert datetime.now().timestamp() - pass_.path("bastion").stat().st_mtime < 60
