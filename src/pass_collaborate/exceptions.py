"""Define program exceptions."""


class NotFoundError(Exception):
    """Model the exception of not finding something."""


class TooManyError(Exception):
    """Model the exception of finding too much."""


class DecryptionError(Exception):
    """Model the exception of problems when decrypting a file."""
