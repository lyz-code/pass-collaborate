"""Configure the dependencies of the program."""

import shutil
from functools import lru_cache
from pathlib import Path

from pydantic import BaseModel  # noqa: E0611

from ..adapters import AuthStore, KeyStore, PassStore


class Dependencies(BaseModel):
    """Configure the dependencies of the program."""

    pass_: PassStore
    auth: AuthStore
    key: KeyStore

    class Config:
        """Configure the pydantic model."""

        arbitrary_types_allowed = True


@lru_cache()
def configure_dependencies(pass_dir: Path, key_dir: Path) -> Dependencies:
    """Configure the program dependencies.

    Args:
        pass_dir: Directory where the `pass` password store data lives.
        key_dir: Directory where the `gnupg` data lives.
    """
    return Dependencies(
        pass_=PassStore(store_dir=pass_dir),
        key=KeyStore(key_dir),
        auth=configure_authentication_store(pass_dir),
    )


@lru_cache()
def configure_authentication_store(pass_dir: Path) -> AuthStore:
    """Configure the Auth adapter.

    Args:
        pass_dir: Directory where the `pass` password store data lives.
    """
    auth_file = (pass_dir / ".auth.yaml").expanduser()
    if not auth_file.exists():
        shutil.copyfile("assets/auth.yaml", auth_file)
    auth = AuthStore()
    auth.load(auth_file)
    return auth
