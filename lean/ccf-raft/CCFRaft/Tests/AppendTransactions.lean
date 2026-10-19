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
open Model (ModelConfig initialNodeState BOOTSTRAP_TERM)

def config : ModelConfig where
  configuration := {0, 1}
  primary := ⟨0, by decide⟩

def initial : NodeState := initialNodeState config 0

def caps :=
  CCF.Capabilities.record (Message := Message) (Notification := Notification) 0

/-- A successful transaction append extends the bootstrap log. -/
theorem transaction_appends
    : ((appendEntry caps 0 initial (.transaction 1 {})).run {}).map
        (fun result => result.1.log)
      = some
          (initial.log
            ++ [{ term := BOOTSTRAP_TERM, content := .transaction 1 {} }]) := by
  decide

/-- The batch fold retains every transaction and the signature in order. -/
theorem batch_appends
    : ((appendBatch caps 0 initial [.transaction 1 {}, .transaction 2 {}, .signature]).run
        {}).map
        (fun result => result.1.log)
      = some
          (initial.log
            ++ [
              { term := BOOTSTRAP_TERM, content := .transaction 1 {} },
              { term := BOOTSTRAP_TERM, content := .transaction 2 {} },
              { term := BOOTSTRAP_TERM, content := .signature }
            ]) := by
  decide

theorem batch_length
    : ((appendBatch caps 0 initial [.transaction 1 {}, .transaction 2 {}, .signature]).run
        {}).map
        (fun result => result.1.log.length)
      = some 4 := by
  decide

/-- A transaction records its resulting configuration, with no intermediate ones. -/
theorem reconfiguration_appends_once
    : ((appendBatch caps 0 initial
          [.transaction 3 { configuration := some {0, 2, 3} }]).run
        {}).map
        (fun result =>
          (
            (configurationHistory result.1.log).map (fun c => (c.index, c.nodes)),
            result.2.outgoing.map (fun envelope => envelope.target)
          ))
      = some ([(1, {0, 1}), (2, {0, 2, 3})], [2, 3]) := by
  cbv

/-- Separate transactions may still change configuration within one batch. -/
theorem multiple_reconfiguration_transactions
    : ((appendBatch caps 0 initial
          [
            .transaction 3 { configuration := some {0, 1, 2} },
            .transaction 4 { configuration := some {0, 2} }
          ]).run
        {}).map
        (fun result =>
          (
            (configurationHistory result.1.log).map (fun c => (c.index, c.nodes)),
            result.2.outgoing.map (fun envelope => envelope.target)
          ))
      = some ([(1, {0, 1}), (2, {0, 1, 2}), (3, {0, 2})], [2]) := by
  cbv

/-- New-peer heartbeats refer to the log before the configuration entry. -/
theorem reconfiguration_heartbeats_use_old_endpoint
    : ((appendBatch caps 0 initial
          [.transaction 3 { configuration := some {0, 2, 3} }]).run
        {}).map
        (fun result =>
          result.2.outgoing.map fun envelope => (envelope.target, envelope.payload))
      = some
          [
            (
              2,
              .appendEntriesRequest
                {
                  term := BOOTSTRAP_TERM,
                  prevLogIndex := 1,
                  prevLogTerm := BOOTSTRAP_TERM,
                  entries := [],
                  primaryCommit := 0
                }
            ),
            (
              3,
              .appendEntriesRequest
                {
                  term := BOOTSTRAP_TERM,
                  prevLogIndex := 1,
                  prevLogTerm := BOOTSTRAP_TERM,
                  entries := [],
                  primaryCommit := 0
                }
            )
          ] := by
  cbv

def beforeRetirementRecord : NodeState :=
  {
    initial with
      log :=
        initial.log
        ++ [
          {
            term := BOOTSTRAP_TERM,
            content := .transaction 1 { configuration := some {0} }
          },
          { term := BOOTSTRAP_TERM, content := .signature }
        ]
      commitIndex := 3
  }

def combinedTransaction : EntryContent :=
  .transaction 4 { configuration := some {0, 2}, retirementConfirmations := {1} }

theorem retirement_only_appends
    : ((appendBatch caps 0 beforeRetirementRecord
          [.transaction 4 { retirementConfirmations := {1} }]).run
        {}).map
        (fun result =>
          (
            result.1.log.length,
            result.1.commitIndex,
            (configurationHistory result.1.log).map (·.index),
            result.2.outgoing.length
          ))
      = some (4, 3, [1, 2], 0) := by
  cbv

/-- Both changes share one entry; retirement confirmation is still uncommitted. -/
theorem combined_metadata_pending
    : ((appendBatch caps 0 beforeRetirementRecord [combinedTransaction]).run {}).map
        (fun result =>
          (
            result.1.log.length,
            result.1.commitIndex,
            result.1.retirementCompletedNodes,
            retiredCommittedNodes result.1.committedLog,
            retiredCommittedNodes result.1.log,
            result.2.outgoing.map (fun envelope => envelope.target)
          ))
      = some (4, 3, {1}, ∅, {1}, [2]) := by
  cbv

/-- A quorum acknowledgement commits both fields at the covering signature. -/
theorem combined_metadata_committed
    : (((do
          let state <- appendBatch caps 0 beforeRetirementRecord
                        [combinedTransaction, .signature]
          handleAppendEntriesResponse caps 0 state 2
            { term := BOOTSTRAP_TERM, success := true, lastLogIndex := 5 })
        : NodeEffect NodeState).run
        {}).map
        (fun result =>
          (
            result.1.commitIndex,
            result.1.retirementCompletedNodes,
            retiredCommittedNodes result.1.committedLog
          ))
      = some (5, ∅, {1}) := by
  cbv

/-- Removing a node does not make its retirement completed in the same transaction. -/
theorem incomplete_retirement_disables_transaction
    : ((appendBatch caps 0 initial
          [.transaction 4
            { configuration := some {0, 2}, retirementConfirmations := {1} }]).run
        {}).isNone
      = true := by
  cbv

/-- A pending retirement record cannot be duplicated by a later transaction. -/
theorem duplicate_retirement_disables_batch
    : ((appendBatch caps 0 beforeRetirementRecord
          [combinedTransaction, .transaction 5 { retirementConfirmations := {1} }]).run
        {}).isNone
      = true := by
  cbv

theorem unchanged_configuration_disables_transaction
    : ((appendBatch caps 0 initial [.transaction 5 { configuration := some {0, 1} }]).run
        {}).isNone
      = true := by
  cbv

/-- A later invalid entry disables the whole batch, not just that entry. -/
theorem failing_batch_discards_outputs
    : ((appendBatch caps 0 initial
          [
            .transaction 5 { configuration := some {0, 1, 2} },
            .transaction 6 { configuration := some ∅ }
          ]).run
        {}).isNone
      = true := by
  cbv

theorem signature_requires_prefix
    : ((appendEntry caps 0 { initial with log := [] } .signature).run {}).isNone
      = true := by
  decide

end CCFRaft.Tests.AppendTransactions
