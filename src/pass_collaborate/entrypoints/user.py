"""User command line interface definition."""

from typing import Optional

import typer
from rich.console import Console

from .. import views
from ..exceptions import NotFoundError

app = typer.Typer()


@app.command()
def add(
    ctx: typer.Context,
    identifier: str = typer.Argument(..., help="GPG identifier"),
    name: Optional[str] = typer.Option(None, help="Overwrite GPG key user name"),
    email: Optional[str] = typer.Option(None, help="Overwrite GPG key email"),
) -> None:
    """Add a new user from the data of the GPG keystore imported keys."""
    pass_ = ctx.obj["pass"]
    try:
        key = pass_.key.find_key(identifier)
    except NotFoundError as error:
        err_console = Console(stderr=True)
        err_console.print(str(error))
        raise typer.Exit(code=404) from error
    if name:
        key.name = name
    if email:
        key.email = email
    pass_.auth.add_user(name=key.name, key=key.id_, email=key.email)


@app.command(name="list")
def list_(ctx: typer.Context) -> None:
    """List existing users."""
    auth = ctx.obj["pass"].auth
    print("\n".join([user.name for user in auth.users]))


@app.command()
def show(
    ctx: typer.Context,
    identifier: str = typer.Argument(
        ..., help="It can be either the name, the email or the gpg key."
    ),
) -> None:
    """Print the information of a user."""
    auth = ctx.obj["pass"].auth
    user = auth.get_user(identifier)
    views.print_model(user)
