## SD Lock / Unlock utility

### Description

A CLI frontend to the SD Connect service, the CSC service for encrypted
object storage for sensitive data.

The CLI tool is meant to simplify the upload of encrypted files, and to
allow the use of the separate lightweight on-demand re-encryption service
bundled together with the main Web UI of SD Connect.

For smaller datasets the Web UI is recommended, but the CLI tool should
work with most datasets that one can encounter.

### Requirements

Python 3.12+ is required.

- The dependencies mentioned in `requirements.txt`
- Information required for access to CSC Allas and SD Connect
    - An openstack rc file containing the project credentials
    - A project-scoped API token generated on the SD Connect Web UI

### Usage

The tool provides two CLI commands, `sd-lock` and `sd-unlock`. As the names
would indicate, the former encrypts (and if needed, uploads) a directory, and
the latter does the opposite. In case the system is short on storage, or the
storage is slow, a direct upload is advised, as it doesn't use disk as an
intermediary storage medium.

Currently the tool doesn't offer built-in checksumming, so the user is
responsible in making sure that the upload has been finished successfully.

#### Getting started
```
git clone https://github.com/CSCfi/sd-lock-util.git
# Alternatively in case you have SSH keys setup for git
# git clone git@github.com:CSCfi/sd-lock-util.git
cd sd-lock-util
pip install -r requirements.txt
pip install .[]
```

#### Configuration
The commands need a few parameters to run. These are the address of the
SD connect runner API, an API token for accessing said API, the container/bucket
name of the files, and an Openstack project name available
(same as MyCSC project ID).

The parameters can be configured either through command-line arguments (as
displayed below) or with the following environment variables:

* `SD_CONNECT_API_TOKEN` – the token for SD Connect API
* `SD_CONNECT_API_ADDRESS` – the address for the SD Connect lock/unlock API
* `OS_PROJECT_NAME` – the name for the Openstack project / id of the MyCSC project
* `UPLOAD_CONTAINER` – the container / bucket used during upload / download

Additionally, if the integrated upload / download feature is to be used,
Openstack access credentials need to be available in order to access Allas.
These can be added in a simple way by sourcing an Openstack environment
configuration (`.rc`) file.

#### Examples
Encrypting a folder without uploading files (with the configured environment)
```
➜ sd-lock --no-content-upload test-folder
```

Decrypting a folder without downloading the files (the files need to be
downloaded separately first, command is used in a confiugred environment)
```
➜ sd-unlock --no-content-download test-folder
```

Fetching the project public key from SD Connect.
```
➜ sd-pubkey > "$(OS_PROJECT_NAME).c4gh.pub"
```

#### Commands
After installing the Python package, following commands will be available:
```
➜ sd-lock-util --help
Usage: sd-lock-util [OPTIONS] COMMAND [ARGS]...

  Group CLI functions into a single tool to simplify using pyinstaller.

Options:
  --version                 Show the version and exit.
  --help                    Show this message and exit.

Commands:
  check-id                  Fetch the project ID information from either share id or name.
  fix-header-permissions    Grant the actual owner project access to the headers.
  fix-missing-headers       Retrieve the missing file headers from the uploading project.
  lock                      Lock a file or folder.
  migrate-headers           Migrate headers from an old bucket to a new one.
  migrate-sharing           Migrate sharing from an old bucket to a new one.
  pubkey                    Fetch and display the project public key.
  push-headers              Consume a header manifest and push headers to vault.
  unlock                    Unlock a file or folder.
```

```
➜ sd-check-id --help
Usage: sd-check-id [OPTIONS] ID

  Fetch the project ID information from either share id or name.

Options:
  --project-id TEXT          Project id of the project used in uploading.
  --project-name TEXT        Project name of the project used in uploading.
  --sd-connect-address TEXT  Address used when connecting to SD Connect.
  --sd-api-token TEXT        Token to use for authentication with SD Connect.
  --no-check-certificate     Don't check TLS certificate for authenticity.
                             (development use only)
  --verbose                  Print more information.
  --debug                    Print debug information.
  --help                     Show this message and exit.
```

```
➜ sd-fix-header-permissions --help
Usage: sd-fix-header-permissions [OPTIONS]

  Grant the actual owner project access to the headers.

Options:
  --container TEXT           Container where the encrypted contents are.
  --project-id TEXT          Project id of the project used when uploading the
                             files.
  --project-name TEXT        Project name of the project used when uploading
                             the files.
  --owner TEXT               Owner of the shared container.
  --owner-name TEXT          Owner name of the shared container.
  --os-auth-url TEXT         Openstack authentication backend URL.
  --sd-connect-address TEXT  Address used when connecting to SD Connect.
  --sd-api-token TEXT        Token to use for authentication with SD Connect.
  --prefix TEXT              Prefix to use with paths when downloading (used
                             for downloading from subfolders).
  --no-check-certificate     Don't check TLS certificate for authenticity.
                             (development use only)
  --verbose                  Print more information.
  --debug                    Print debug information.
  --help                     Show this message and exit.
```

```
➜ sd-fix-missing-headers --help
Usage: sd-fix-missing-headers [OPTIONS]

  Retrieve the missing file headers from the uploading project.

Options:
  --container TEXT           Container where the encrypted contents are.
  --project-id TEXT          Project id of the project that should own the
                             encrypted files.
  --project-name TEXT        Project name of the project that should own the
                             encrypted files.
  --owner TEXT               Sharing ID of the original uploader of the
                             encrypted files.
  --owner-name TEXT          Project name of the original uploader of the
                             encrpyted files.
  --os-auth-url TEXT         Openstack authentication backend URL.
  --sd-connect-address TEXT  Address used when connecting to SD Connect.
  --sd-api-token TEXT        Token to use for authentication with SD Connect.
  --prefix TEXT              Prefix to use with paths when downloading (used
                             for downloading from subfolders).
  --no-check-certificate     Don't check TLS certificate for authenticity.
                             (development use only)
  --verbose                  Print more information.
  --debug                    Print debug information.
  --help                     Show this message and exit.
```

```
➜ sd-lock --help
Usage: sd-lock [OPTIONS] PATH

  Lock a file or folder.

Options:
  --container TEXT           Container where the files will be uploaded.
  --project-id TEXT          Project id of the project used in uploading.
  --project-name TEXT        Project name of the project used in uploading.
  --owner TEXT               Owner of the shared container.
  --os-auth-url TEXT         Openstack authentication backend URL.
  --sd-connect-address TEXT  Address used when connecting to SD Connect.
  --sd-api-token TEXT        Token to use for authentication with SD Connect.
  --isolated                 Run without SD Connect API connection.
  --project-public-key TEXT  Project public key for header encryption in
                             isolated mode.
  --no-content-upload        Upload headers and encrypt in place. User will
                             provide the upload script afterwards.
  --no-preserve-original     Remove original files after encrypting.
  --no-check-certificate     Don't check TLS certificate for authenticity.
                             (development use only)
  --no-check-certificate     Don't check TLS certificate for authenticity.
                             (development use only)
  --verbose                  Print more information.
  --debug                    Print debug information.
  --progress                 Display file progress information.
  --help                     Show this message and exit.
```

```
➜ sd-migrate-headers --help
Usage: sd-migrate-headers [OPTIONS] FROM_BUCKET TO_BUCKET

  Migrate headers from an old bucket to a new one.

  The script assumes the objects keys and layout hasn't changed before
  migration. This means that in no situation should you change the name of any
  object within the copied bucket before migrating over the headers. Headers
  are tracked internally by the object key, and will either be attached to the
  incorrect object or skipped in retrieval.

Options:
  --project-id TEXT          Project id of the project that owns the source
                             and destination buckets.
  --project-name TEXT        Project name of the project that owns the source
                             and destination buckets.
  --os-auth-url TEXT         Openstack authentication backend URL.
  --sd-connect-address TEXT  Address used when connecting to SD Connect.
  --sd-api-token TEXT        Token to use for authentication with SD Connect.
  --no-check-certificate     Don't check TLS certificate for authenticity.
                             (development use only)
  --verbose                  Print more information.
  --debug                    Print debug information.
  --help                     Show this message and exit.
```

```
➜ sd-migrate-sharing --help
Usage: sd-migrate-sharing [OPTIONS] FROM_BUCKET TO_BUCKET

  Migrate sharing from an old bucket to a new one.

  The script migrates both the Swift sharing ACL to an S3 bucket policy
  compatible format, and the possible Vault shraing if it exists (granting the
  header access for read and write sharing levels).

Options:
  --project-id TEXT          Project id of the project that owns the source
                             and destination buckets.
  --project-name TEXT        Project name of the project that owns the source
                             and destination buckets.
  --os-auth-url TEXT         Openstack authentication backend URL.
  --sd-connect-address TEXT  Address used when connecting to SD Connect.
  --sd-api-token TEXT        Token to use for authentication with SD Connect.
  --no-check-certificate     Don't check TLS certificate for authenticity.
                             (development use only)
  --verbose                  Print more information.
  --ec2-key TEXT             EC2 key.
  --ec2-secret TEXT          EC2 secret.
  --s3-endpoint-url TEXT     S3 endpoint url.
  --debug                    Print debug information.
  --help                     Show this message and exit.
```

```
➜ sd-pubkey --help
Usage: sd-pubkey [OPTIONS]

  Fetch and display the project public key.

Options:
  --project-id TEXT          Project id of the project used in uploading.
  --project-name TEXT        Project name of the project used in uploading.
  --owner TEXT               Owner of the shared container.
  --owner-name TEXT          Owner name of the shared container.
  --sd-connect-address TEXT  Address used when connecting to SD Connect.
  --sd-api-token TEXT        Token to use for authentication with SD Connect.
  --no-check-certificate     Don't check TLS certificate for authenticity.
                             (development use only)
  --verbose                  Print more information.
  --debug                    Print debug information.
  --help                     Show this message and exit.
```

```
➜ sd-push-headers --help
Usage: sd-push-headers [OPTIONS] PATH

  Consume a header manifest and push headers to vault.

Options:
  --container TEXT           Container where the files will be uploaded.
  --project-id TEXT          Project id of the project used in uploading.
  --project-name TEXT        Project name of the project used in uploading.
  --owner TEXT               Owner of the shared container.
  --owner-name TEXT          Owner name of the shared container.
  --sd-connect-address TEXT  Address used when connecting to SD Connect.
  --sd-api-token TEXT        Token to use for authentication with SD Connect.
  --no-check-certificate     Don't check TLS certificate for authenticity.
                             (development use only)
  --verbose                  Print more information.
  --debug                    Print debug information.
  --help                     Show this message and exit.
```

```
➜ sd-unlock --help
Usage: sd-unlock [OPTIONS]

  Unlock a file or folder.

Options:
  --container TEXT           Container where the files were downloaded from.
  --project-id TEXT          Project id of the project used in downloading.
  --project-name TEXT        Project name of the project used in downloading.
  --owner TEXT               Owner of the shared container.
  --os-auth-url TEXT         Openstack authentication backend URL.
  --sd-connect-address TEXT  Address used when connecting to SD Connect.
  --sd-api-token TEXT        Token to use for authentication with SD Connect.
  --path TEXT                Path where the downloaded files are.
  --no-content-download      Download headers and decrypt in place. User will
                             provide the files to decrypt.
  --no-preserve-original     Remove original files after decrypting.
  --no-check-certificate     Don't check TLS certificate for authenticity.
                             (development use only)
  --verbose                  Print more information.
  --debug                    Print debug information.
  --progress                 Display file progress information.
  --help                     Show this message and exit.
```

### License

``sd_lock_utility`` and all it sources are released under *MIT License*.
