#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -eu
PLATFORM=${PLATFORM:-virtual}
my_app_target=my_app
# Run the sample app in a container
docker run \
    --name ccf \
    --rm -v "$(pwd)/app:/app" \
    -p 8080:8080 \
    ${my_app_target} cchost --config /app/cchost_config_${PLATFORM}_js.json &

sleep 3 && docker rm -f ccf
