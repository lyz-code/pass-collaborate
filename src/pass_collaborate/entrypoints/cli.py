"""Command line interface definition."""

from pathlib import Path
from typing import Optional

import typer
from pydantic import ValidationError
from rich.console import Console

from .. import views
from ..exceptions import NotFoundError
from ..model.pass_ import PassStore
from ..version import version_info
from . import group, load_logger, user

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
# R0913: Too many arguments for the function, but we need them to define the command
#   line interface
@app.callback()
def main(  # noqa: R0913
    ctx: typer.Context,
    version: Optional[bool] = typer.Option(  # noqa: W0613, M511, B008
        None, "--version", callback=version_callback, is_eager=True
    ),
    pass_dir: Path = typer.Option(  # noqa: M511, B008
        "~/.password-store", envvar="PASSWORD_STORE_DIR"
    ),
    key_dir: Path = typer.Option("~/.gnupg", envvar="GNUPGHOME"),  # noqa: M511, B008
    auth_dir: Optional[Path] = typer.Option(  # noqa: M511, B008
        None,
        envvar="PASSWORD_AUTH_DIR",
        help=(
            "Relative path from the root of the password store to the directory "
            "where the .auth.yaml lives"
        ),
    ),
    verbose: bool = False,
) -> None:
    """A pass extension that helps collectives manage the access to their passwords."""
    ctx.ensure_object(dict)
    err_console = Console(stderr=True)
    load_logger(verbose)
    try:
        ctx.obj["pass"] = PassStore(
            store_dir=pass_dir.expanduser(),
            key_dir=key_dir.expanduser(),
            auth_dir=auth_dir,
        )
    except NotFoundError as error:
        err_console.print(str(error))
        raise typer.Exit(code=404) from error
    except ValidationError as error:
        err_console.print(str(error))
        raise typer.Exit(code=2) from error


@app.command()
def access(
    ctx: typer.Context,
    identifier: str = typer.Argument(
        ...,
        help=(
            "Unique identifier of the user or group who's access to check. "
            "It can be a user name, email, gpg key or group name."
        ),
    ),
) -> None:
    """Check what passwords does the user or group have access to."""
    pass_ = ctx.obj["pass"]
    paths = pass_.access(identifier)
    views.print_access(label=identifier, paths=paths)


if __name__ == "__main__":
    app()
