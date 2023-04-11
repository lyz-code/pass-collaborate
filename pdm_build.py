"""Script to create the needed files in the user's device."""

import os
from pathlib import Path
import shutil

def pdm_build_update_files(context, files):
    """Create the needed files in the user's device.

    `pdm` will run this script when installing the application.

    Args:
        src: the path to the source directory
        dst: the path to the distribution directory
    """

    if 'PASSWORD_STORE_EXTENSIONS_DIR' in os.environ:
        lib = Path(os.environ['PASSWORD_STORE_EXTENSIONS_DIR'])
    else:
        lib = Path.home() / '.password-store' / '.extensions'

    for file in ['user.bash', 'group.bash', 'access.bash']:
        files[f"assets/{file}"] = lib / file
