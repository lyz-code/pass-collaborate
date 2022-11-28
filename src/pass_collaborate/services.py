"""Define all the orchestration functionality required by the program to work.

Classes and functions that connect the different domain model objects with the adapters
and handlers to achieve the program's purpose.
"""


def has_access(auth: "AuthStore", pass_: "PassStore", element: str) -> bool:
    """Return if the user of the password store has access to an element of the store.

    Args:
        auth: Adapter of the authorisation store
        pass: Adapter of the password store of the user to test
        element: identifier of a password store element.
    """
    ...
