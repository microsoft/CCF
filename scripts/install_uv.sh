#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -euo pipefail

UV_VERSION=0.11.19
install_dir=${1:-/usr/local/bin}

case "$(uname -m)" in
    x86_64)
        target=x86_64-unknown-linux-gnu
        checksum=7035608168e106375b36d0c818d537a889c51a8625fe7f8f7cad5e62b947c368
        ;;
    aarch64|arm64)
        target=aarch64-unknown-linux-gnu
        checksum=83b13ab184a45b7d9a3b0e4b10eaebd50ad41e66cb16dcce8e60aa7be13ae399
        ;;
    *)
        echo "Unsupported architecture for uv: $(uname -m)" >&2
        exit 1
        ;;
esac

if [[ -x "$install_dir/uv" && -x "$install_dir/uvx" ]] &&
    [[ "$("$install_dir/uv" --version)" == "uv ${UV_VERSION}"* ]]; then
    exit 0
fi

if command -v uv >/dev/null 2>&1 &&
    command -v uvx >/dev/null 2>&1 &&
    [[ "$(uv --version)" == "uv ${UV_VERSION}"* ]]; then
    exit 0
fi

mkdir -p "$install_dir"

python3 - "$UV_VERSION" "$target" "$checksum" "$install_dir" <<'PY'
import hashlib
import os
from pathlib import Path
import shutil
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request

version, target, expected_checksum, install_dir_arg = sys.argv[1:]
archive_name = f"uv-{target}.tar.gz"
url = f"https://github.com/astral-sh/uv/releases/download/{version}/{archive_name}"
install_dir = Path(install_dir_arg)

with tempfile.TemporaryDirectory(prefix="ccf-install-uv-") as temporary_dir:
    archive_path = Path(temporary_dir) / archive_name
    request = urllib.request.Request(url, headers={"User-Agent": "CCF uv installer"})
    for attempt in range(3):
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                with archive_path.open("wb") as output:
                    shutil.copyfileobj(response, output)
            break
        except (TimeoutError, urllib.error.URLError):
            if attempt == 2:
                raise
            time.sleep(1 if attempt == 0 else 5)

    actual_checksum = hashlib.sha256(archive_path.read_bytes()).hexdigest()
    if actual_checksum != expected_checksum:
        raise RuntimeError(
            f"Invalid SHA-256 for {archive_name}: "
            f"expected {expected_checksum}, got {actual_checksum}"
        )

    with tarfile.open(archive_path, "r:gz") as archive:
        for binary in ("uv", "uvx"):
            member = archive.getmember(f"uv-{target}/{binary}")
            source = archive.extractfile(member)
            if source is None:
                raise RuntimeError(f"Could not extract {binary} from {archive_name}")

            destination = install_dir / binary
            with tempfile.NamedTemporaryFile(
                dir=install_dir, prefix=f".{binary}.", delete=False
            ) as output:
                temporary_destination = Path(output.name)
                shutil.copyfileobj(source, output)
            temporary_destination.chmod(0o755)
            os.replace(temporary_destination, destination)

print(f"Installed uv {version} to {install_dir}")
PY

"$install_dir/uv" --version
