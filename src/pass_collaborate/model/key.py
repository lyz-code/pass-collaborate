"""Define the model of the key objects."""

from typing import Generator, List, Optional, Annotated, Dict, Any
from pydantic import BaseModel, EmailStr, Field, root_validator  # noqa: E0611

GPGKey = Annotated[str, Field(regex="^[0-9A-Z]{40}$")]
