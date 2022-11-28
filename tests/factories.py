"""Define the factories of the program."""

from typing import Any

from pydantic_factories import ModelFactory

from pass_collaborate import model


class GroupFactory(ModelFactory[Any]):
    """Define factory for the Group model."""

    __model__ = model.Group


class UserFactory(ModelFactory[Any]):
    """Define factory for the Group model."""

    __model__ = model.User
