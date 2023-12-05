#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -ex

if [ -f /aci_env ]; then
    source /aci_env
fi

# Our linter, shellcheck, expects (reasonably) that env vars are all caps. Alas.
# shellcheck disable=SC2154
if [ -z "${Fabric_NodeIPOrFQDN}" ]; then
    URL="http://169.254.254.169"
else
    URL="http://${Fabric_NodeIPOrFQDN}:2377"
fi

curl -s "${URL}/metadata/THIM/amd/certification" -H "Metadata: true" | jq