"""Define the configuration of the main program."""

import os
from enum import Enum

from goodconf import GoodConf


class LogLevel(str, Enum):
    """Define the possible log levels."""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"

class Config(GoodConf):  # type: ignore
    """Define the configuration of the program."""

    log_level: LogLevel = LogLevel.INFO

    class Config:
        """Define the default files to check."""

        default_files = [
            os.path.expanduser("~/.local/share/pass_collaborate/config.yaml"),
            "config.yaml"
        ]
