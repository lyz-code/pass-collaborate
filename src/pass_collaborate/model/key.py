"""Define the model of the key objects."""

try:
    from typing import Annotated  # type: ignore
except ImportError:
    from typing_extensions import Annotated

from pydantic import Field  # noqa: E0611

# mypy is complaining that it can't import Annotated, but it's solved with the except
GPGKey = Annotated[str, Field(regex="^[0-9A-Z]{16,40}$")]
