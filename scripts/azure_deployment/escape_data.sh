# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

# Escape newlines for Azure pipeline
# https://learn.microsoft.com/en-us/azure/devops/pipelines/process/set-variables-scripts?view=azure-devops&tabs=bash
escape_data() {
    local data=$1
    data="${data//'%'/'%AZP25'}"
    data="${data//$'\n'/'%0A'}"
    data="${data//$'\r'/'%0D'}"
    echo "$data"
}
