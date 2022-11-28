"""Command line interface definition."""

from pathlib import Path
from typing import Optional

import typer

from .. import version, views
from . import group, user
from .dependencies import configure_dependencies

app = typer.Typer()
app.add_typer(group.app, name="group")
app.add_typer(user.app, name="user")


def version_callback(value: bool) -> None:
    """Print the version of the program."""
    if value:
        print(version.version_info())
        raise typer.Exit()


@app.callback()
def main(
    ctx: typer.Context,
    version: Optional[bool] = typer.Option(
        None, "--version", callback=version_callback, is_eager=True
    ),
    pass_dir: Path = typer.Option("~/.password-store", envvar="PASSWORD_STORE_DIR"),
    key_dir: Path = typer.Option("~/.gnupg", envvar="GNUPGHOME"),
) -> None:
    """A pass extension that helps collectives manage the access to their passwords."""
    ctx.ensure_object(dict)
    ctx.obj["deps"] = configure_dependencies(pass_dir=pass_dir, key_dir=key_dir)


if __name__ == "__main__":
    app()
