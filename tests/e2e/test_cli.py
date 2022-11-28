"""Test the command line interface."""

import logging
import os
import re
from typing import TYPE_CHECKING

from typer.testing import CliRunner

from pass_collaborate.entrypoints.cli import app
from pass_collaborate.version import __version__

if TYPE_CHECKING:
    from pass_collaborate.adapters import AuthStore

log = logging.getLogger(__name__)


def test_version(runner: CliRunner) -> None:
    """Prints program version when called with --version."""
    result = runner.invoke(app, ["--version"])

    assert result.exit_code == 0
    assert re.search(
        rf" *pass_collaborate: {__version__}\n *Python: .*\n *Platform: .*",
        result.stdout,
    )


def test_generates_default_conf_if_none_is_available(
    runner: CliRunner, auth: "AuthStore"
) -> None:
    """
    Given: An environment without an auth config file.
    When: calling an auth related command.
    Then: The config file is created with a template.
    """
    os.remove(auth.config_file)

    result = runner.invoke(app, ["group", "add", "test_group"])

    assert result.exit_code == 0
    assert os.path.exists(auth.config_file)
