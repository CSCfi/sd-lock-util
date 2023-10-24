"""SD Lock Utility exceptions."""


class NoToken(Exception):
    """No token was provided for establishing API connection."""


class NoAddress(Exception):
    """No address was provided for establishing API connection."""


class NoProject(Exception):
    """No project was provided."""


class NoContainer(Exception):
    """No container was provided."""


class NoKey(Exception):
    """Could not fetch the key."""


class NoWhitelistAccess(Exception):
    """Could not add a new key to the whitelist."""


class NoHeaderPushAccess(Exception):
    """Could not add a file header."""


class NoFileHeader(Exception):
    """Could not find a file header."""
