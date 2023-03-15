"""Script to create the needed files in the user's device."""

import os
from pathlib import Path
import shutil

def build(src, dst):
    """Create the needed files in the user's device.

    `pdm` will run this script when installing the application.

    Args:
        src: the path to the source directory
        dst: the path to the distribution directory
    """

    # Configure the extensions
    if 'PASSWORD_STORE_EXTENSIONS_DIR' in os.environ:
        lib = Path(os.environ['PASSWORD_STORE_EXTENSIONS_DIR'])
    else:
        lib = Path.home() / '.password-store' / '.extensions'
    os.makedirs(lib, exist_ok=True)

    for file in ['user.bash', 'group.bash', 'access.bash']:
        shutil.copyfile(f"assets/{file}", lib / file)
        os.chmod(lib / file, 0o755)

    # Enable the extensions
    for file in ['.bashrc', '.zshrc']:
        config = Path.home() / file
        if config.exists():
            if 'export PASSWORD_STORE_ENABLE_EXTENSIONS=true' not in config.read_text():
                with config.open('a') as f:
                    f.write('export PASSWORD_STORE_ENABLE_EXTENSIONS=true')
