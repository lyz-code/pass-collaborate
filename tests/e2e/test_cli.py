"""Test the command line interface."""

import logging
import os
import re
from typing import TYPE_CHECKING

from _pytest.logging import LogCaptureFixture
from typer.testing import CliRunner

from pass_collaborate.entrypoints.cli import app
from pass_collaborate.version import __version__

from ..factories import UserFactory

if TYPE_CHECKING:
    from pass_collaborate.model.pass_ import PassStore


log = logging.getLogger(__name__)


def test_version(runner: CliRunner) -> None:
    """Prints program version when called with --version."""
    result = runner.invoke(app, ["--version"])

    assert result.exit_code == 0
    assert re.search(
        rf" *pass_collaborate: {__version__}\n *Python: .*\n *Platform: .*",
        result.stdout,
    )


def test_generates_default_auth_conf_if_none_is_available(
    runner: CliRunner, pass_: "PassStore"
) -> None:
    """
    Given: An environment without an auth config file.
    When: calling an auth related command.
    Then: The config file is created with a template.
    """
    os.remove(pass_.auth.config_file)

    result = runner.invoke(app, ["group", "add", "test_group"])

    assert result.exit_code == 0
    assert os.path.exists(pass_.auth.config_file)


def test_pass_returns_error_when_no_keys_are_found(
    runner: CliRunner, pass_: "PassStore", caplog: LogCaptureFixture
) -> None:
    """
    Given: A password store that uses a GPG key that is not on our keystore
    When: calling any pass_collaborate command
    Then: An error is returned
    """
    runner.mix_stderr = False
    user = UserFactory.build()
    gpg_id = pass_.store_dir / ".gpg-id"
    gpg_id.write_text(user.key)

    result = runner.invoke(app, ["access", user.name])

    assert result.exit_code == 404
    assert (
        f"Please import the gpg key {user.key} in your gpg \nkeystore\n"
        in result.stderr
    )
