"""Test the command line interface."""

import logging
import re
from pathlib import Path

import pytest
from _pytest.logging import LogCaptureFixture
from click.testing import CliRunner

from pass_collaborate.config import Config
from pass_collaborate.entrypoints.cli import cli
from pass_collaborate.version import __version__

log = logging.getLogger(__name__)


@pytest.fixture(name="runner")
def fixture_runner(config: Config) -> CliRunner:
    """Configure the Click cli test runner."""
    return CliRunner(
        mix_stderr=False, env={"PASS_COLLABORATE_CONFIG_PATH": config.config_path}
    )


def test_version(runner: CliRunner) -> None:
    """Prints program version when called with --version."""
    result = runner.invoke(cli, ["--version"])

    assert result.exit_code == 0
    assert re.search(
        rf" *pass_collaborate: {__version__}\n *Python: .*\n *Platform: .*",
        result.stdout,
    )


def test_load_config_handles_configerror_exceptions(
    runner: CliRunner, tmp_path: Path, caplog: LogCaptureFixture
) -> None:
    """
    Given: A wrong configuration file.
    When: CLI is initialized
    Then: The ConfigError exception is gracefully handled.
    """
    config_file = tmp_path / "config.yaml"
    config_file.write_text("[ invalid yaml")

    result = runner.invoke(cli, ["-c", str(config_file), "null"])

    assert result.exit_code == 1
    assert (
        "pass_collaborate.entrypoints",
        logging.ERROR,
        f'Configuration Error: while parsing a flow sequence\n  in "{config_file}", '
        "line 1, column 1\nexpected ',' or ']', but got '<stream end>'\n  in"
        f' "{config_file}", line 1, column 15',
    ) in caplog.record_tuples
