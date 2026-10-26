module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import CCFRaft.Replay.Reduction

public section

namespace CCFRaft.Replay

/-- Prepared initialization and instructions for direct model replay. -/
structure Reduced where
  header : Header
  instructions : Array Instruction

/-- Validate records, prepare identities, and reduce their ordered Events. -/
def reduce (records : Array Record) : Except String Reduced := do
  let (events, declared) ← associate records
  let locations :=
    (events.toList.filter (fun event => event.function == "replicate")).map
      (·.record.location)
  require (locations.eraseDups == locations) "duplicate transaction source location"
  let requests := "" :: locations
  let header : Header := { bootstrap := ∅, declared, requests }
  let (leader, instructions) ← Reducer.reduce events header
  let header := { header with bootstrap := {← header.nodeId leader} }
  return { header, instructions }

def replayRecords (records : Array Record) : Except String Result := do
  let reduced ← reduce records
  replay reduced.header reduced.instructions

end CCFRaft.Replay
