#!/usr/bin/env bash
set -euo pipefail

ASSET_NAME="${1:-sd-lock-util-legacy}"
PYTHON_VERSION="${PYTHON_VERSION:-3.12.12}"
export PYENV_ROOT="${PYENV_ROOT:-/root/.pyenv}"

echo "Installing deps"
dnf install -y \
    gcc make patch zlib-devel bzip2 bzip2-devel readline-devel \
    sqlite sqlite-devel openssl-devel tk-devel libffi-devel \
    xz-devel wget curl git

dnf clean all

echo "Installing pyenv"
git clone https://github.com/pyenv/pyenv.git ${PYENV_ROOT}

export PATH="$PYENV_ROOT/bin:$PYENV_ROOT/shims:$PATH"

eval "$("$PYENV_ROOT/bin/pyenv" init -)"

echo "Installing Python ${PYTHON_VERSION}..."
pyenv install -s "$PYTHON_VERSION"
pyenv local "$PYTHON_VERSION"

echo ">>> Verifying installation..."
python --version

echo "Installing Python deps"
python -m ensurepip || true
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

echo "Installing PyInstaller"
python -m pip install pyinstaller pyinstaller-versionfile

echo "Building binary"
python -m PyInstaller --onefile sd_lock_utility/cli.py \
  --name "${ASSET_NAME}" \
  --hidden-import=_cffi_backend \
  --collect-all sd_lock_utility \
  --collect-all aioboto3 \
  --collect-all aiobotocore \
  --collect-submodules boto3 \
  --collect-submodules botocore

echo "Build complete"
ls -lah dist/
