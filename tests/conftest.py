"""Store the classes and fixtures used throughout the tests."""

import shutil
from pathlib import Path

import pytest
from pydantic import EmailStr

from pass_collaborate.adapters import AuthStore, KeyStore, PassStore
from pass_collaborate.entrypoints.dependencies import (
    Dependencies,
    configure_dependencies,
)
from pass_collaborate.model import User


@pytest.fixture(name="work_dir")
def work_dir_(tmp_path: Path) -> Path:
    """Create the work directory for the tests."""
    shutil.copytree("tests/assets/pass", tmp_path / ".password-store")
    shutil.copytree("tests/assets/gpg", tmp_path / "gpg")
    return tmp_path


@pytest.fixture(name="deps")
def deps_(work_dir: Path) -> Dependencies:
    """Create the Dependencies of the program."""
    return configure_dependencies(
        pass_dir=(work_dir / ".password-store"), key_dir=(work_dir / "gpg" / "admin")
    )


@pytest.fixture(name="auth")
def auth_(deps: Dependencies) -> AuthStore:
    """Create an AuthStore on the working dir."""
    return deps.auth


@pytest.fixture(name="pass_")
def pass_(deps: Dependencies) -> PassStore:
    """Create an PassStore with admin rights."""
    return deps.pass_


@pytest.fixture(name="key")
def key_(deps: Dependencies) -> KeyStore:
    """Create a KeyStore with admin rights."""
    return deps.key


@pytest.fixture(name="key_dev")
def key_dev_(work_dir: Path) -> KeyStore:
    """Create an KeyStore with developer rights."""
    gpg_dir = work_dir / "gpg" / "developer"
    return KeyStore(key_dir=gpg_dir)


@pytest.fixture(name="key_attacker")
def key_attack_(work_dir: Path) -> KeyStore:
    """Create an KeyStore with attacker rights."""
    gpg_dir = work_dir / "gpg" / "attacker"
    return KeyStore(key_dir=gpg_dir)


@pytest.fixture(name="developer")
def developer_() -> User:
    """Create the developer user."""
    return User(
        name="Marie",
        email=EmailStr("developer@example.org"),
        key="8DFE8782CD025ED6220D305115575911602DDD94",
    )
