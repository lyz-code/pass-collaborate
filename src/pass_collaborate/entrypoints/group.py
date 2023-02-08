"""Group command line interface definition."""

from typing import List, Optional

import typer
from rich.console import Console

from .. import exceptions, services, version, views

app = typer.Typer()


@app.command()
def add(
    ctx: typer.Context, name: str, users: Optional[List[str]] = typer.Argument(None)
) -> None:
    """Add a new group.

    Args:
        name: name of the group
        users: users to add to the group.
    """
    auth = ctx.obj["pass"].auth
    auth.add_group(name=name, users=users)


@app.command()
def add_users(ctx: typer.Context, identifiers: List[str], group_name: str) -> None:
    """Add a list of users to an existent group.

    Args:
        identifiers: Unique identifiers of users to add. It can be user names, emails or gpg keys.
        group_name: name of the group
    """
    ctx.obj["pass"].change_group_users(
        group_name=group_name, add_identifiers=identifiers
    )


@app.command()
def remove_users(ctx: typer.Context, identifiers: List[str], group_name: str) -> None:
    """Remove a list of users from an existent group.

    Args:
        identifiers: Unique identifiers of users to remove. It can be the user names, emails or gpg keys.
        group_name: name of the group
    """
    ctx.obj["pass"].change_group_users(
        group_name=group_name, remove_identifiers=identifiers
    )


@app.command()
def list(ctx: typer.Context) -> None:
    """List existing groups.

    Args:
        ctx: Click context
    """
    auth = ctx.obj["pass"].auth
    print("\n".join(auth.group_names))


@app.command()
def show(ctx: typer.Context, name: str) -> None:
    """Print the information of a group.

    Args:
        ctx: Click context
        name: name of the group
    """
    auth = ctx.obj["pass"].auth
    group = auth.get_group(name)
    views.print_model(group)


@app.command()
def authorize(ctx: typer.Context, id_: str, pass_path: str) -> None:
    """Authorize a group or person to a directory of the password store.

    Args:
        ctx: Click context
        id_: Unique identifier of a group or person. It can be the group name, person
            name, email or gpg key.
        path: directory to give access to.
    """
    pass_ = ctx.obj["pass"]
    err_console = Console(stderr=True)
    try:
        pass_.authorize(pass_dir_path=pass_path, id_=id_)
    except ValueError as error:
        err_console.print(str(error))
        raise typer.Exit(code=2) from error
    except exceptions.TooManyError as error:
        err_console.print(str(error))
        raise typer.Exit(code=401) from error


if __name__ == "__main__":
    app()
