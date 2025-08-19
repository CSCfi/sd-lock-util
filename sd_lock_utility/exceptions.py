"""SD Lock Utility exceptions."""


class NoToken(Exception):
    """No token was provided for establishing API connection."""


class NoAddress(Exception):
    """No address was provided for establishing API connection."""


class NoProject(Exception):
    """No project was provided."""


class NoOwner(Exception):
    """Provided owner project could not be used (missing mapping of id to name)."""


class NoContainer(Exception):
    """No container was provided."""


class NoOwnerNameForSharedContainer(Exception):
    """No owner name found for shared bucket."""


class ContainerCreationFailed(Exception):
    """Could not access or create the required container for upload."""


class NoContainerAccess(Exception):
    """Could not access the required container."""


class NoKey(Exception):
    """Could not fetch the key."""


class NoWhitelistAccess(Exception):
    """Could not add a new key to the whitelist."""


class NoHeaderPushAccess(Exception):
    """Could not add a file header."""


class NoFileHeader(Exception):
    """Could not find a file header."""


class HandleClientExceptions(Exception):
    """Class for gracefully handling exceptions generating by the client."""


class SkipIteratorCancel(Exception):
    """Replace iterator cancellation with another exception to prevent graceful cancel from running."""


class NoClient(Exception):
    """For some reason the session didn't have a ClientSession available."""
