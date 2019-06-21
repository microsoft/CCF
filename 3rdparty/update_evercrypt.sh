#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

#
# This script should be used to update 3rdparty/evercrypt from the docker image
# provided by evercrypt.
#       https://hub.docker.com/r/projecteverest/hacl-star-linux/tags
#
# Usage: ./update_evercrypt.sh projecteverest/hacl-star-linux:<some_hash>
#            [destination_directory]
#

set -ex

function cleanup {
  docker kill "$container_id"
  docker rm "$container_id"
}

CONTAINER_EVEREST_DIRECTORY="/home/everest"
CONTAINER_CCF_DIST_DIRECTORY="/home/everest/hacl-star/dist/ccf"
CONTAINER_KREMLIN_DIRECTORY="/home/everest/hacl-star/kremlin/include"
CONTAINER_KREMLIB_DIRECTORY="/home/everest/hacl-star/kremlin/kremlib/dist/minimal"

DEFAULT_EVERCRYPT_DIRECTORY="evercrypt"

if [ -z "$2" ]; then
    evercrypt_directory=$DEFAULT_EVERCRYPT_DIRECTORY
else
    evercrypt_directory=$2
fi

# Pull image, start container and check that the build was successful
docker pull "$1"

container_id="$(docker run -d "$1" | head -1)"
trap cleanup EXIT

build_status="$(docker exec "$container_id" cat "$CONTAINER_EVEREST_DIRECTORY"/result.txt)"

if [ "$build_status" != "Success" ]; then
    echo "ERROR: Build status was {$build_status}"
    exit 1
fi

# Copy Hacl* source and Kremlin from container
docker cp "$container_id":$CONTAINER_CCF_DIST_DIRECTORY "$evercrypt_directory"
docker cp "$container_id":$CONTAINER_KREMLIN_DIRECTORY "$evercrypt_directory"/kremlin
docker cp "$container_id":$CONTAINER_KREMLIB_DIRECTORY "$evercrypt_directory"/kremlin/kremlib

# Only keep Hacl* source files
rm "$evercrypt_directory"/{*.[oda],*.asm,Makefile*,*.so}
rm "$evercrypt_directory"/kremlin/kremlib/{*.[oda],Makefile*}

# Finally, record build version (container hash is also git hash of hacl-star
# repo fstar-master branch)
echo "$1" > "$evercrypt_directory"/version.txt