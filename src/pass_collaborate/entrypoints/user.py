"""User command line interface definition."""

import typer

app = typer.Typer()


@app.command()
def add(
    ctx: typer.Context,
    name: str = typer.Argument(..., help="Name of the user"),
    key: str = typer.Argument(..., help="GPG key of the user"),
    email: str = typer.Argument(..., help="Email of the user"),
) -> None:
    """Add a new user."""
    auth = ctx.obj["pass"].auth
    auth.add_user(name=name, key=key, email=email)
