"""Group command line interface definition."""

from typing import List, Optional

import typer

from .. import version, views

app = typer.Typer()


@app.command()
def add(
    ctx: typer.Context, name: str, users: Optional[List[str]] = typer.Argument(None)
) -> None:
    """Add a new group.

    Args:
        ctx: Click context
        name: name of the group
        users: users to add to the group.
    """
    auth = ctx.obj["deps"].auth
    auth.add_group(name=name, users=users)


@app.command()
def add_users(ctx: typer.Context, users: List[str], name: str) -> None:
    """Add a list of users to an existent group.

    Args:
        ctx: Click context
        users: users to add to the group.
        name: name of the group
    """
    auth = ctx.obj["deps"].auth
    auth.add_users_to_group(name=name, users=users)


@app.command()
def list(ctx: typer.Context) -> None:
    """List existing groups.

    Args:
        ctx: Click context
    """
    auth = ctx.obj["deps"].auth
    print("\n".join(auth.group_names))


@app.command()
def show(ctx: typer.Context, name: str) -> None:
    """Print the information of a group.

    Args:
        ctx: Click context
        name: name of the group
    """
    auth = ctx.obj["deps"].auth
    group = auth.get_group(name)
    views.print_model(group)


if __name__ == "__main__":
    app()
