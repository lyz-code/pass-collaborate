"""Define the views of the program."""

from pathlib import Path
from typing import Dict, List

from pydantic import BaseModel  # noqa: E0611
from rich.console import Console
from rich.table import Table
from rich.tree import Tree


def print_model(model: BaseModel) -> None:
    """Print the attributes of a model.

    Args:
        model: A pydantic model.
    """
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

    Console().print(table)


def print_access(label: str, paths: List[str]) -> None:
    """Print the password paths a user or group has access to.

    Args:
        label: Entity we're printing the access to the password store.
        paths: List of `pass` paths that the entity has access to.
    """
    # Create the tree structure
    tree = Tree(f"Password access for {label}")
    trees: Dict[str, Tree] = {}

    for _path in paths:
        path = Path(_path)
        for parent in list(path.parents)[::-1]:
            if str(parent) == ".":
                continue
            try:
                active_tree = trees[str(parent)]
            except KeyError:
                if str(parent.parent) == ".":
                    active_tree = tree.add(str(parent))
                else:
                    active_tree = active_tree.add(parent.name)
                trees[str(parent)] = active_tree
        active_tree.add(path.name)

    Console().print(tree)
