#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -u

if [ "$#" -eq 0 ]; then
  echo "check-todo.sh takes at least one file or directory"
  exit 1
fi

TODOS=$(grep -r TODO "$@")

if [ "$TODOS" == "" ]; then
  echo "No TODOs found"
else
  echo "$TODOS"
  exit 1
fi