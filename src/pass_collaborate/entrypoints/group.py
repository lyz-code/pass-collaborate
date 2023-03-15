"""Group command line interface definition."""

from typing import List, Optional

import typer
from rich.console import Console

from .. import exceptions, views

app = typer.Typer()


@app.command()
def add(
    ctx: typer.Context,
    name: str = typer.Argument(
        ...,
        help="name of the group",
    ),
    user_ids: Optional[List[str]] = typer.Argument(
        None,
        help=(
            "Identifiers of the users to add to the group. It can be name, "
            "email or GPG key id."
        ),
    ),
) -> None:
    """Add a new group."""
    auth = ctx.obj["pass"].auth
    auth.add_group(name=name, user_ids=user_ids)


@app.command()
def add_users(
    ctx: typer.Context,
    identifiers: List[str] = typer.Argument(
        ...,
        help=(
            "Unique identifiers of users to add. "
            "It can be user names, emails or gpg keys."
        ),
    ),
    group_name: str = typer.Argument(...),
) -> None:
    """Add a list of users to an existent group."""
    try:
        ctx.obj["pass"].change_group_users(
            group_name=group_name, add_identifiers=identifiers
        )
    except exceptions.EncryptionError as error:
        err_console = Console(stderr=True)
        err_console.print(str(error))
        err_console.print(
            "Please reset the state of your password directory, "
            "fix the origin of the error and try again"
        )
        raise typer.Exit(code=2) from error


@app.command()
def remove_users(  # noqa: B008
    ctx: typer.Context,
    identifiers: List[str] = typer.Argument(
        ...,
        help=(
            "Unique identifiers of users to remove. "
            "It can be user names, emails or gpg keys."
        ),
    ),
    group_name: str = typer.Argument(...),
) -> None:
    """Remove a list of users from an existent group."""
    try:
        ctx.obj["pass"].change_group_users(
            group_name=group_name, remove_identifiers=identifiers
        )
    except exceptions.EncryptionError as error:
        err_console = Console(stderr=True)
        err_console.print(str(error))
        err_console.print(
            "Please reset the state of your password directory, "
            "fix the origin of the error and try again"
        )
        raise typer.Exit(code=2) from error


@app.command(name="list")
def list_(ctx: typer.Context) -> None:
    """List existing groups."""
    auth = ctx.obj["pass"].auth
    print("\n".join(auth.group_names))


@app.command()
def show(ctx: typer.Context, name: str) -> None:
    """Print the information of a group."""
    auth = ctx.obj["pass"].auth
    group, users = auth.get_group(name)
    views.print_group(group, users)


@app.command()
def authorize(  # noqa: B008
    ctx: typer.Context,
    group_name: str,
    pass_paths: List[str] = typer.Argument(
        ..., help="pass directories to give access to."
    ),
    ignore_parent: bool = typer.Option(
        False,
        help="Ignore the access permissions defined in the parent .gpg-id",
    ),
) -> None:
    """Authorize a group to a directory of the password store."""
    pass_ = ctx.obj["pass"]
    err_console = Console(stderr=True)
    for path in pass_paths:
        try:
            pass_.change_access(
                pass_dir_path=path,
                add_identifiers=[group_name],
                ignore_parent=ignore_parent,
            )
        except ValueError as error:
            err_console.print(str(error))
            raise typer.Exit(code=2) from error
        except exceptions.TooManyError as error:
            err_console.print(str(error))
            raise typer.Exit(code=401) from error
        except exceptions.NotFoundError as error:
            err_console.print(str(error))
            raise typer.Exit(code=401) from error


@app.command()
def revoke(  # noqa: B008
    ctx: typer.Context,
    group_name: str,
    pass_paths: List[str] = typer.Argument(
        ..., help="pass directories to give access to."
    ),
) -> None:
    """Revoke a group to a directory of the password store."""
    pass_ = ctx.obj["pass"]
    err_console = Console(stderr=True)
    for path in pass_paths:
        try:
            pass_.change_access(
                pass_dir_path=path,
                remove_identifiers=[group_name],
            )
        except ValueError as error:
            err_console.print(str(error))
            raise typer.Exit(code=2) from error
        except exceptions.TooManyError as error:
            err_console.print(str(error))
            raise typer.Exit(code=401) from error
        except exceptions.NotFoundError as error:
            err_console.print(str(error))
            raise typer.Exit(code=401) from error


if __name__ == "__main__":
    app()
