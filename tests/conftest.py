"""Store the classes and fixtures used throughout the tests."""

import shutil
from pathlib import Path

import pytest
from pydantic import EmailStr
from typer.testing import CliRunner

from pass_collaborate.adapters import KeyStore
from pass_collaborate.model.auth import AuthStore, User
from pass_collaborate.model.pass_ import PassStore


@pytest.fixture(name="work_dir")
def work_dir_(tmp_path: Path) -> Path:
    """Create the work directory for the tests."""
    shutil.copytree("tests/assets/pass", tmp_path / ".password-store")
    shutil.copytree("tests/assets/gpg", tmp_path / "gpg")
    return tmp_path


@pytest.fixture(name="pass_")
def pass__(work_dir: Path) -> PassStore:
    """Create the password store for an admin."""
    return PassStore(
        store_dir=(work_dir / ".password-store"), key_dir=(work_dir / "gpg" / "admin")
    )


@pytest.fixture(name="pass_dev")
def pass_dev_(work_dir: Path) -> PassStore:
    """Create the password store for a developer."""
    return PassStore(
        store_dir=(work_dir / ".password-store"),
        key_dir=(work_dir / "gpg" / "developer"),
    )


@pytest.fixture(name="pass_attacker")
def pass_attacker_(work_dir: Path) -> PassStore:
    """Create the password store for an attacker."""
    return PassStore(
        store_dir=(work_dir / ".password-store"),
        key_dir=(work_dir / "gpg" / "attacker"),
    )


@pytest.fixture(name="admin")
def admin_() -> User:
    """Create the admin user."""
    return User(
        name="admin",
        email=EmailStr("admin@example.org"),
        key="5E435D54DDC11A0F303910AEDECE5B3C889F13DE",
    )


@pytest.fixture(name="developer")
def developer_() -> User:
    """Create the developer user."""
    return User(
        name="developer",
        email=EmailStr("developer@example.org"),
        key="8DFE8782CD025ED6220D305115575911602DDD94",
    )


@pytest.fixture(name="attacker")
def attacker_() -> User:
    """Create the attacker user."""
    return User(
        name="Mallory",
        email=EmailStr("mallory@example.org"),
        key="C810FD864F7BAED8AD1D233C6E3A5366E18CBE77",
    )


@pytest.fixture(name="auth")
def auth_(work_dir: Path) -> AuthStore:
    """Create the password store for an admin."""
    auth = AuthStore()
    auth.load(str(work_dir / ".password-store" / ".auth.yaml"))
    return auth


@pytest.fixture(name="key")
def key_(work_dir: Path) -> KeyStore:
    """Create the password store for an admin."""
    return KeyStore(key_dir=work_dir / "gpg" / "admin")


@pytest.fixture(name="cli_runner")
def runner_(work_dir: Path) -> CliRunner:
    """Configure the typer cli runner."""
    return CliRunner(
        env={
            "PASSWORD_STORE_DIR": str(work_dir / ".password-store"),
            "GNUPGHOME": str(work_dir / "gpg" / "admin"),
            "PASSWORD_AUTH_DIR": "",
        },
        mix_stderr=False,
    )
