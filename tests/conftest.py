"""Store the classes and fixtures used throughout the tests."""

import shutil
from pathlib import Path

import pytest
from pydantic import EmailStr

from pass_collaborate.adapters import AuthStore, PassStore
from pass_collaborate.entrypoints.dependencies import configure_password_store
from pass_collaborate.model import User


@pytest.fixture(name="work_dir")
def work_dir_(tmp_path: Path) -> Path:
    """Create the work directory for the tests."""
    shutil.copytree("tests/assets/pass", tmp_path / ".password-store")
    shutil.copytree("tests/assets/gpg", tmp_path / "gpg")
    return tmp_path


@pytest.fixture(name="auth")
def auth_(work_dir: Path) -> AuthStore:
    """Create an AuthStore on the working dir."""
    auth_file = work_dir / ".password-store" / ".auth.yaml"
    auth_file.touch()
    auth = AuthStore()
    auth.load(auth_file)
    return auth


@pytest.fixture(name="pass_")
def pass_(work_dir: Path) -> PassStore:
    """Create an PassStore with admin rights."""
    return configure_password_store(
        pass_dir=work_dir / ".password-store",
        key_dir=work_dir / "gpg" / "admin",
    )


@pytest.fixture(name="pass_dev")
def pass_dev_(work_dir: Path) -> PassStore:
    """Create an PassStore with admin rights."""
    return configure_password_store(
        pass_dir=work_dir / ".password-store",
        key_dir=work_dir / "gpg" / "developer",
    )


@pytest.fixture(name="pass_attack")
def pass_attack_(work_dir: Path) -> PassStore:
    """Create an PassStore with admin rights."""
    return configure_password_store(
        pass_dir=work_dir / ".password-store",
        key_dir=work_dir / "gpg" / "attacker",
    )


@pytest.fixture(name="developer")
def developer_() -> User:
    """Create the developer user."""
    return User(
        name="Marie",
        email=EmailStr("developer@example.org"),
        key="8DFE8782CD025ED6220D305115575911602DDD94",
    )
