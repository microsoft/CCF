module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all Init.Control.State
import all Init.Data.List.Sort.Basic

public import CCFRaft.Model

@[expose] public section

/-!
Kernel-checked regressions that transactions extend the log and batch folding
retains every entry in order.
-/

namespace CCFRaft.Tests.AppendTransactions

open Model.Node

def config : InitialConfig Nat where
  configuration := {0, 1}
  leader := 0
  leader_mem := by decide

def initial : NodeState Nat Nat := initialNodeState config 0

def caps :=
  CCF.Capabilities.record (Message := Message Nat Nat) (Notification := Notification) 0

/-- A successful transaction append extends the bootstrap log. -/
theorem transaction_appends
    : ((appendEntry config caps 0 initial (.transaction 1 [])).run {}).map
        (fun result => result.1.log)
      = some
          (initial.log
            ++ [{ term := BOOTSTRAP_TERM, content := .transaction 1 [] }]) := by
  decide

/-- The batch fold retains every transaction and the signature in order. -/
theorem batch_appends
    : ((appendBatch config caps 0 initial
          [.transaction 1 [], .transaction 2 [], .signature]).run
        {}).map
        (fun result => result.1.log)
      = some
          (initial.log
            ++ [
              { term := BOOTSTRAP_TERM, content := .transaction 1 [] },
              { term := BOOTSTRAP_TERM, content := .transaction 2 [] },
              { term := BOOTSTRAP_TERM, content := .signature }
            ]) := by
  decide

theorem batch_length
    : ((appendBatch config caps 0 initial
          [.transaction 1 [], .transaction 2 [], .signature]).run
        {}).map
        (fun result => result.1.log.length)
      = some 4 := by
  decide

/-- Multiple reconfiguration effects in one transaction remain ordered. -/
theorem multiple_reconfigurations
    : ((appendBatch config caps 0 initial
          [.transaction 3 [.reconfiguration {0, 1, 2}, .reconfiguration {0, 2}]]).run
        {}).map
        (fun result =>
          (
            (configurationHistory config result.1.log).map (fun c => (c.index, c.nodes)),
            result.2.outgoing.map (fun envelope => envelope.target)
          ))
      = some ([(0, {0, 1}), (1, {0, 1}), (2, {0, 1, 2}), (2, {0, 2})], [2]) := by
  cbv

/-- A later failing effect discards outputs already emitted by its transaction. -/
theorem failing_transaction_discards_outputs
    : ((appendBatch config caps 0 initial
          [.transaction 4 [.reconfiguration {0, 1, 2}, .reconfiguration {}]]).run
        {}).isNone
      = true := by
  cbv

/-- A later invalid entry disables the whole batch, not just that entry. -/
theorem failing_batch_discards_outputs
    : ((appendBatch config caps 0 initial
          [
            .transaction 5 [.reconfiguration {0, 1, 2}],
            .transaction 6 [.reconfiguration {}]
          ]).run
        {}).isNone
      = true := by
  cbv

end CCFRaft.Tests.AppendTransactions
