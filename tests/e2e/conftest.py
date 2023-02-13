"""Define the fixtures of the e2e tests."""

from pathlib import Path

import pytest
from typer.testing import CliRunner


@pytest.fixture(name="runner")
def fixture_runner(work_dir: Path) -> CliRunner:
    """Configure the Click cli test runner."""
    return CliRunner(
        env={
            "PASSWORD_STORE_DIR": str(work_dir / ".password-store"),
            "GNUPGHOME": str(work_dir / "gpg" / "admin"),
        }
    )
