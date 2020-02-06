#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -u

if [ "$#" -ne 1 ]; then
  echo "check-todo.sh takes a single file or directory"
  exit 1
fi

TODOS=$(grep -r TODO $1)

if [ "$TODOS" == "" ]; then
  echo "No TODOs found"
else
  echo "$TODOS"
  exit 1
fi