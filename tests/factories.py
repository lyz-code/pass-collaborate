"""Define the factories of the program."""

from typing import Any

from pydantic_factories import ModelFactory

from pass_collaborate.model import auth


class GroupFactory(ModelFactory[Any]):
    """Define factory for the Group model."""

    __model__ = auth.Group


class UserFactory(ModelFactory[Any]):
    """Define factory for the Group model."""

    __model__ = auth.User
