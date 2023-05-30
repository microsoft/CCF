#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -e

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <path_to_proto_file> <output_directory>"
fi

THIS_DIR=$( dirname "${BASH_SOURCE[0]}" )
SOURCE_FILE=${1}
GENERATED_DIR=${2}

if [ ! -f "env/bin/activate" ]
    then
        python3.10 -m venv env
fi

source env/bin/activate
pip install -q -U -r "${THIS_DIR}/requirements.txt"

mkdir -p "${GENERATED_DIR}"

echo " -- Building ${SOURCE_FILE}"
python -m grpc_tools.protoc \
        -I "${THIS_DIR}" \
        --python_out "${GENERATED_DIR}" \
        --grpc_python_out "${GENERATED_DIR}" \
        "${SOURCE_FILE}"