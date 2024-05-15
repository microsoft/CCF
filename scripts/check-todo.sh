#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -u

if [ "$#" -eq 0 ]; then
  echo "check-todo.sh takes at least one file or directory"
  exit 1
fi

DENYLIST="TODO FIXME"
STATUS=0

for DENYTERM in $DENYLIST; do
  FOUND=$(git ls-files ":!:3rdparty" ":!:.github/ISSUE_TEMPLATE" ":!:scripts/ci-checks.sh" ":!:scripts/check-todo.sh" ":!:Doxyfile" "$@" | xargs grep -n "$DENYTERM")

  if [ "$FOUND" == "" ]; then
    echo "No ${DENYTERM}s found"
  else
    echo "$FOUND"
    STATUS=1
  fi
done

exit $STATUS
