"""SD Lock Utility exceptions."""


class NoToken(Exception):
    """No token was provided for establishing API connection."""


class NoAddress(Exception):
    """No address was provided for establishing API connection."""


class NoProjectName(Exception):
    """No project name was provided."""


class NoProjectId(Exception):
    """No project id was provided."""


class NoOwner(Exception):
    """Provided owner project could not be used (missing mapping of id to name)."""


class NoContainer(Exception):
    """No container was provided."""


class NoDestinationBucket(Exception):
    """No destination bucket was provided."""


class NoOwnerNameForSharedContainer(Exception):
    """No owner name found for shared bucket."""


class ContainerCreationFailed(Exception):
    """Could not access or create the required container for upload."""


class NoContainerAccess(Exception):
    """Could not access the required container."""


class S3IncompatibleBucketName(Exception):
    """The chosen bucket name is incompatible for access using the S3 API."""


class NoKey(Exception):
    """Could not fetch the key."""


class NoKeyProvided(Exception):
    """No key was provided in isolated mode."""


class NoHeaderManifest(Exception):
    """Header manifest not provided or is malformed."""


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


class NoS3Client(Exception):
    """For some reason the session didn't have a S3Client available."""


class NoS3Access(Exception):
    """Trying to configure S3 using identity API, but failed."""


class Unauthorized(Exception):
    """Raised when API returns HTTP 401 Unauthorized."""


class ManifestMismatch(Exception):
    """Provided project information differs from manifest."""


class NoOwnerOrOwnerNameProvided(Exception):
    """In isolated mode, missing either owner or owner name."""


class NoOpenstackCredentials(Exception):
    """Missing Openstack username and/or password."""


class NoAuthenticationURL(Exception):
    """Missing Openstack authentication URL."""
