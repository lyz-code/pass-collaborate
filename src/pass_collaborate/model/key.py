"""Define the model of the key objects."""

try:
    from typing import Annotated
except ImportError:
    from typing_extensions import Annotated

from pydantic import Field  # noqa: E0611

GPGKey = Annotated[str, Field(regex="^[0-9A-Z]{16,40}$")]
