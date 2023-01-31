"""Store the classes and fixtures used throughout the tests."""

import shutil
from pathlib import Path

import pytest
from pydantic import EmailStr

from pass_collaborate.model.auth import User, AuthStore
from pass_collaborate.model.pass_ import PassStore
from pass_collaborate.adapters import KeyStore


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
        store_dir=(work_dir / ".password-store"), key_dir=(work_dir / "gpg" / "developer")
    )

@pytest.fixture(name="pass_attacker")
def pass_attacker_(work_dir: Path) -> PassStore:
    """Create the password store for an attacker."""
    return PassStore(
        store_dir=(work_dir / ".password-store"), key_dir=(work_dir / "gpg" / "attacker")
    )

@pytest.fixture(name="developer")
def developer_() -> User:
    """Create the developer user."""
    return User(
        name="Marie",
        email=EmailStr("developer@example.org"),
        key="8DFE8782CD025ED6220D305115575911602DDD94",
    )

@pytest.fixture(name="auth")
def auth_(work_dir: Path) -> AuthStore:
    """Create the password store for an admin."""
    auth = AuthStore()
    auth_file = auth.check_auth_file(work_dir / '.password-store')
    auth.load(auth_file)
    return auth

@pytest.fixture(name="key")
def key_(work_dir: Path) -> KeyStore:
    """Create the password store for an admin."""
    return KeyStore(key_dir=(work_dir / 'gpg' / 'admin'))
