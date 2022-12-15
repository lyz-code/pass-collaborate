"""Command line interface definition."""

from pathlib import Path
from typing import Optional

import typer

from ..version import version_info
from . import group, user
from .dependencies import configure_dependencies

app = typer.Typer()
app.add_typer(group.app, name="group")
app.add_typer(user.app, name="user")


def version_callback(value: bool) -> None:
    """Print the version of the program."""
    if value:
        print(version_info())
        raise typer.Exit()


# W0613: version is not used, but it is
# M511: - mutable default arg of type Call, it's how it's defined
# B008: Do not perform function calls in argument defaults. It's how it's defined
@app.callback()
def main(
    ctx: typer.Context,
    version: Optional[bool] = typer.Option(  # noqa: W0613, M511, B008
        None, "--version", callback=version_callback, is_eager=True
    ),
    pass_dir: Path = typer.Option(  # noqa: M511, B008
        "~/.password-store", envvar="PASSWORD_STORE_DIR"
    ),
    key_dir: Path = typer.Option("~/.gnupg", envvar="GNUPGHOME"),  # noqa: M511, B008
) -> None:
    """A pass extension that helps collectives manage the access to their passwords."""
    ctx.ensure_object(dict)
    ctx.obj["deps"] = configure_dependencies(pass_dir=pass_dir, key_dir=key_dir)


if __name__ == "__main__":
    app()
