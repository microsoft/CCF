#!/bin/bash

set -eu

PLATFORM=${PLATFORM:-virtual}
CCF_VERSION=${CCF_VERSION:-$(curl -Ls -o /dev/null -w '%{url_effective}' https://github.com/microsoft/CCF/releases/latest | sed 's/^.*ccf-//')}
ccf_target=ccf_runtime

docker build \
    -t ${ccf_target} \
    --no-cache \
    --build-arg PLATFORM=$PLATFORM \
    --build-arg CCF_VERSION=$CCF_VERSION \
    -f ./${ccf_target}/Dockerfile \
    .

# Using ccf_runtime image to the sample app build to use as final image
my_app_target=my_app
MYAPP_VERSION=${MYAPP_VERSION:-$(curl -Ls -o /dev/null -w '%{url_effective}' https://github.com/microsoft/CCF/releases/latest | sed 's/^.*ccf-//')}
docker build \
    -t ${my_app_target} \
    --no-cache \
    --build-arg PLATFORM=$PLATFORM \
    --build-arg MYAPP_VERSION=$MYAPP_VERSION \
    --build-arg CCF_RUNTIME_IMAGE=${ccf_target} \
    -f ./${my_app_target}/Dockerfile \
    .
