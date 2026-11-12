-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

meta import Kv.Model

public import Kv.Model

public section

/-! Direct semantic executions: no trace envelopes, reported values, schema, or test scopes. -/

namespace Kv.Tests.Semantics

open Kv.Model

private def run (s : State) (inputs : List Action) : IO State :=
  inputs.foldlM
    (fun before action =>
      match execute before action with
      | some (after, _) => pure after
      | none => throw (IO.userError s!"disabled semantic input: {repr action}"))
    s

private def result (s : State) (action : Action) (expected : Output) : IO State := do
  match execute s action with
  | none => throw (IO.userError s!"disabled semantic input: {repr action}")
  | some (next, actual) =>
      if actual ≠ expected then
        throw
          (IO.userError s!"semantic result: expected {repr expected}, got {repr actual}")
      if transitionSystem.step s action ≠ some next then
        throw (IO.userError "semantic transition system is disconnected from execution")
      return next

private def interleaved : IO Unit := do
  let mut s ←
    run {}
      [
        .storeCreate 1 7,
        .storeCreate 2 3,
        .txCreate 1 1,
        .txCreate 1 2,
        .txCreate 2 3,
        .snapshot 1 1,
        .acquire 1 1 "m",
        .snapshot 1 2,
        .acquire 1 2 "m",
        .snapshot 2 3,
        .acquire 2 3 "q",
        .operation 1 2 (.write "m" "k" (some "new")),
        .operation 2 3 (.write "q" "k" (some "other")),
        .commitBegin 1 2,
        .commitBegin 2 3
      ]
  s ← result s (.apply 1 2) (.applied 1 7 [(("m", "k"), some "new")])
  s ← result s (.apply 2 3) (.applied 1 3 [(("q", "k"), some "other")])
  s ← result s (.commitResult 1 2 .noReplicate) (.committed .noReplicate 1)
  s ← result s (.operation 1 1 (.get "m" "k" false)) (.value none)
  s ← run s [.operation 1 1 (.write "m" "j" (some "staged")), .commitBegin 1 1]
  if (step s (.apply 1 1)).isSome then
    throw
      (IO.userError
        "interleaved publication did not invalidate the absent-key dependency")
  s ← result s (.commitResult 1 1 .conflict) (.committed .conflict 0)
  s ← run s [.txEnd 1 1, .txCreate 1 1, .snapshot 1 1, .acquire 1 1 "m"]
  let _ ← result s (.operation 1 1 (.get "m" "k" false)) (.value (some "new"))
  let before := (find s.stores 1).get!
  s ← run s [.rollback 1 0 8]
  s ←
    run s
      [
        .txEnd 1 1,
        .txCreate 1 1,
        .snapshot 1 1,
        .acquire 1 1 "m",
        .operation 1 1 (.write "m" "k" (some "branch")),
        .commitBegin 1 1,
        .apply 1 1
      ]
  let after := (find s.stores 1).get!
  if after.head.version != before.head.version
      || (revision after.head "m").identity == (revision before.head "m").identity then
    throw (IO.userError "rollback reused an application identity")

private def lazyRollback : IO Unit := do
  let mut s ← run {} [.storeCreate 1 7]
  for (tid, value) in [(1, "old"), (2, "new")] do
    s ←
      run s
        [
          .txCreate 1 tid,
          .snapshot 1 tid,
          .acquire 1 tid "a",
          .acquire 1 tid "b",
          .operation 1 tid (.write "a" "k" (some value)),
          .operation 1 tid (.write "b" "k" (some value)),
          .commitBegin 1 tid,
          .apply 1 tid,
          .commitResult 1 tid .success,
          .txEnd 1 tid
        ]
  s ← run s [.txCreate 1 3, .snapshot 1 3, .acquire 1 3 "a", .rollback 1 1 8]
  s ← result s (.acquire 1 3 "b") (.acquired 1 0)
  s ← result s (.operation 1 3 (.get "a" "k" false)) (.value (some "new"))
  s ← result s (.operation 1 3 (.get "b" "k" false)) (.value (some "old"))
  s ← run s [.commitBegin 1 3]
  let _ ← result s (.commitResult 1 3 .success) (.committed .success 0)

private def globalFrames : IO Unit := do
  let mut s ← run {} [.storeCreate 1 4]
  for tid in [1, 2] do
    s ←
      run s
        [
          .txCreate 1 tid,
          .snapshot 1 tid,
          .acquire 1 tid "a",
          .acquire 1 tid "b",
          .operation 1 tid (.write "a" "k" (some (toString tid))),
          .operation 1 tid (.write "b" "k" (some (toString tid))),
          .commitBegin 1 tid,
          .apply 1 tid,
          .commitResult 1 tid .success,
          .txEnd 1 tid
        ]
  s ←
    run s
      [
        .compact 1 1,
        .txCreate 1 3,
        .snapshot 1 3,
        .acquire 1 3 "a",
        .compact 1 2,
        .acquire 1 3 "b"
      ]
  s ← result s (.operation 1 3 (.get "a" "k" true)) (.value (some "1"))
  let _ ← result s (.operation 1 3 (.get "b" "k" true)) (.value (some "2"))

private def check : IO Unit := do
  interleaved
  lazyRollback
  globalFrames
  IO.println "direct semantic model tests passed"

#eval check

end Kv.Tests.Semantics
