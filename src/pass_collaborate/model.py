"""Define the data models of the program."""

from typing import Annotated, List, Optional

from pydantic import BaseModel, EmailStr, Field  # noqa: E0611

Name = Annotated[str, Field(regex="^[0-9a-zA-Z_ ]+$")]
Username = Name
GPGKey = Annotated[str, Field(regex="^[0-9A-Z]{40}$")]


class Group(BaseModel):
    """Model a group of users."""

    name: Name
    users: Optional[List[Username]] = None


class User(BaseModel):
    """Model a user of the password store."""

    name: Username
    email: EmailStr
    key: GPGKey
