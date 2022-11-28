"""Define the views of the program."""

from pydantic import BaseModel  # noqa: E0611
from rich.console import Console
from rich.table import Table


def print_model(model: BaseModel) -> None:
    """Print the attributes of a model.

    Args:
        model: A pydantic model.
    """
    console = Console()

    table = Table(box=None, show_header=False)
    table.add_column("Type", justify="center", style="green", no_wrap=True)
    table.add_column("Value")
    for attribute, schema in model.schema()["properties"].items():
        if schema["type"] == "string":
            table.add_row(schema["title"], getattr(model, attribute))
        elif schema["type"] == "array":
            table.add_row(
                schema["title"], "- " + "\n- ".join(getattr(model, attribute))
            )

    console.print(table)
