-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import Scenarios

/-- Run one of the scenarios, named by the first argument. -/
def main (args : List String) : IO Unit :=
  CftDriver.run args
