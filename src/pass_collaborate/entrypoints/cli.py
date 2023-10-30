"""Command line interface definition."""

import logging
import os
import shutil
import sys
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

log = logging.getLogger(__name__)

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
    auth_dir: Path = typer.Option(  # noqa: M511, B008
        Path(""),
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
    deep: bool = typer.Option(
        False,
        help=(
            "Enable to analyze the keys allowed for each file instead of trusting the "
            ".gpg-id files."
        ),
    ),
) -> None:
    """Check what passwords does the user or group have access to."""
    err_console = Console(stderr=True)
    pass_ = ctx.obj["pass"]
    if deep:
        log.info("If you have many files using --deep may be slow")

    try:
        paths = pass_.access(identifier, deep)
    except NotFoundError as error:
        err_console.print(str(error))
        raise typer.Exit(code=404) from error

    views.print_access(label=identifier, paths=paths)


@app.command()
def reencrypt(
    ctx: typer.Context,
) -> None:
    """Re-encrypt the whole password store."""
    pass_ = ctx.obj["pass"]
    pass_.reencrypt()


@app.command()
def init() -> None:
    """Create the needed files in the user's device."""
    if "PASSWORD_STORE_EXTENSIONS_DIR" in os.environ:
        lib = Path(os.environ["PASSWORD_STORE_EXTENSIONS_DIR"])
    else:
        lib = Path.home() / ".password-store" / ".extensions"
    log.debug(f"Creating the {lib} directory")
    os.makedirs(lib, exist_ok=True)

    log.debug("Copying the plugin files")
    package_directory = sys.modules["pass_collaborate"].__path__[0]
    for filename in ["user.bash", "group.bash", "access.bash"]:
        shutil.copyfile(f"{package_directory}/assets/{filename}", lib / filename)
        # nosec: We need the files to be executable
        os.chmod(lib / filename, 0o755)  # nosec

    # Enable the extensions
    for filename in [".bashrc", ".zshrc"]:
        config = Path.home() / filename
        if (
            config.exists()
            and "export PASSWORD_STORE_ENABLE_EXTENSIONS=true" not in config.read_text()
        ):
            log.debug(f"Enabling the pass extensions in {config}")
            with config.open("a") as file_descriptor:
                file_descriptor.write("export PASSWORD_STORE_ENABLE_EXTENSIONS=true")
            log.info(f"Please reload your terminal configuration with source {config}")


if __name__ == "__main__":
    app()
