"""Define all the orchestration functionality required by the program to work.

Classes and functions that connect the different domain model objects with the adapters
and handlers to achieve the program's purpose.
"""

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .adapters import AuthStore, PassStore

log = logging.getLogger(__name__)


def has_access(pass_: "PassStore", pass_path: str) -> bool:
    """Return if the user of the password store has access to an element of the store.

    Args:
        pass_: Adapter of the password store of the user to test
        pass_path: identifier of a password store element.
    """
    return pass_.has_access(pass_path)
