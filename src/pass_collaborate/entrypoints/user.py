"""User command line interface definition."""

import typer

app = typer.Typer()


@app.command()
def add(
    ctx: typer.Context,
    name: str,
    key: str,
    email: str,
) -> None:
    """Add a new user.

    Args:
        ctx: Click context.
        name: Name of the user.
        key: GPG key of the user.
        email: Email of the user.
    """
    auth= ctx.obj["pass"].auth
    auth.add_user(name=name, key=key, email=email)
