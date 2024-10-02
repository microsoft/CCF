#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

# When finding a counterexample is the expected outcome from TLC
# The debug invariant(s) should be the only invariant(s), otherwise 
# this script might falsely return without errors

./tlc.py "$@"
status=$?

# TLC safety violation returns error code 12 
# https://github.com/tlaplus/tlaplus/blob/a41cbafc66b1dd225156aaca38ad35ec330f4ae9/tlatools/org.lamport.tlatools/src/tlc2/output/EC.java#L350

if [ $status -eq 12 ]; then
  echo "Counterexample found as expected."
  exit 0
elif [ $status -eq 0 ]; then
  echo "Counterexample expected but not found."  >&2
  exit 1
  else
  exit $status
fi