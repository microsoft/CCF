-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Model

/-!
Kernel-checked regressions for the transaction branch's enclosing append
continuation and the batch fold's accumulator.
-/

namespace CCFRaft.Tests.AppendTransactions

open Model.Local

private def config : InitialConfig Nat where
  configuration := {0, 1}
  leader := 0
  leader_mem := by decide

private def initial : NodeState Nat Nat := initialNodeState config 0

private def caps :=
  Shared.Capabilities.record (Message := Message Nat Nat) (Notification := Notification) 0

/-- A successful transaction append extends the bootstrap log. -/
theorem transaction_appends
    : ((appendEntry config caps 0 initial (.transaction 1 [])).run {}).map
        (fun result => result.1.log)
      = some (initial.log ++ [{ term := BOOTSTRAP_TERM, content := .transaction 1 [] }]) := by
  decide

/-- The batch fold retains every transaction and the signature in order. -/
theorem batch_appends
    : ((appendBatch config caps 0 initial
          [.transaction 1 [], .transaction 2 [], .signature]).run
        {}).map
        (fun result => result.1.log)
      = some (initial.log ++ [
          { term := BOOTSTRAP_TERM, content := .transaction 1 [] },
          { term := BOOTSTRAP_TERM, content := .transaction 2 [] },
          { term := BOOTSTRAP_TERM, content := .signature }
        ]) := by
  decide

theorem batch_length :
    ((appendBatch config caps 0 initial
      [.transaction 1 [], .transaction 2 [], .signature]).run {}).map
      (fun result => result.1.log.length) = some 4 := by
  decide

end CCFRaft.Tests.AppendTransactions
