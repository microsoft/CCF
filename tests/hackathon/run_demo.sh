#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

if [ "$#" -eq 0 ]; then
  echo "No args given - specify file to be loaded"
  exit 1
fi

datafile=$1

python3 "../tests/hackathon/loader.py" "-b" "." "--label" "lua_logging_client_test" "-l" "info" "-g" "../src/runtime_config/gov.lua" --app-script ../src/apps/logging/sample.lua --lua-script ../tests/hackathon/checker.lua --datafile $datafile --run-poll 1>>transactions.log
