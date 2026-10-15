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
    : ((appendEntry config caps 0 initial (.transaction 1 {})).run {}).map
        (fun result => result.1.log)
      = some
          (initial.log
            ++ [{ term := BOOTSTRAP_TERM, content := .transaction 1 {} }]) := by
  decide

/-- The batch fold retains every transaction and the signature in order. -/
theorem batch_appends
    : ((appendBatch config caps 0 initial
          [.transaction 1 {}, .transaction 2 {}, .signature]).run
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
    : ((appendBatch config caps 0 initial
          [.transaction 1 {}, .transaction 2 {}, .signature]).run
        {}).map
        (fun result => result.1.log.length)
      = some 4 := by
  decide

/-- A transaction records its resulting configuration, with no intermediate ones. -/
theorem reconfiguration_appends_once
    : ((appendBatch config caps 0 initial
          [.transaction 3 { configuration := some {0, 2, 3} }]).run
        {}).map
        (fun result =>
          (
            (configurationHistory config result.1.log).map (fun c => (c.index, c.nodes)),
            result.2.outgoing.map (fun envelope => envelope.target)
          ))
      = some ([(0, {0, 1}), (1, {0, 1}), (2, {0, 2, 3})], [2, 3]) := by
  cbv

/-- Separate transactions may still change configuration within one batch. -/
theorem multiple_reconfiguration_transactions
    : ((appendBatch config caps 0 initial
          [
            .transaction 3 { configuration := some {0, 1, 2} },
            .transaction 4 { configuration := some {0, 2} }
          ]).run
        {}).map
        (fun result =>
          (
            (configurationHistory config result.1.log).map (fun c => (c.index, c.nodes)),
            result.2.outgoing.map (fun envelope => envelope.target)
          ))
      = some ([(0, {0, 1}), (1, {0, 1}), (2, {0, 1, 2}), (3, {0, 2})], [2]) := by
  cbv

/-- New-peer heartbeats refer to the log before the configuration entry. -/
theorem reconfiguration_heartbeats_use_old_endpoint
    : ((appendBatch config caps 0 initial
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
                  leaderCommit := 0
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
                  leaderCommit := 0
                }
            )
          ] := by
  cbv

def beforeRetirementRecord : NodeState Nat Nat :=
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

def combinedTransaction : EntryContent Nat Nat :=
  .transaction 4 { configuration := some {0, 2}, retiredCommitted := {1} }

theorem retirement_only_appends
    : ((appendBatch config caps 0 beforeRetirementRecord
          [.transaction 4 { retiredCommitted := {1} }]).run
        {}).map
        (fun result =>
          (
            result.1.log.length,
            result.1.commitIndex,
            (configurationHistory config result.1.log).map (·.index),
            result.2.outgoing.length
          ))
      = some (4, 3, [0, 1, 2], 0) := by
  cbv

/-- Both changes share one entry; retirement confirmation is still uncommitted. -/
theorem combined_metadata_pending
    : ((appendBatch config caps 0 beforeRetirementRecord [combinedTransaction]).run
        {}).map
        (fun result =>
          (
            result.1.log.length,
            result.1.commitIndex,
            result.1.retirementCompletedNodes config,
            retiredCommittedNodes result.1.committedLog,
            retiredCommittedNodes result.1.log,
            result.2.outgoing.map (fun envelope => envelope.target)
          ))
      = some (4, 3, {1}, ∅, {1}, [2]) := by
  cbv

/-- A quorum acknowledgement commits both fields at the covering signature. -/
theorem combined_metadata_committed
    : (((do
          let state <- appendBatch config caps 0 beforeRetirementRecord
                        [combinedTransaction, .signature]
          handleAppendEntriesResponse config caps 0 state 2
            { term := BOOTSTRAP_TERM, success := true, lastLogIndex := 5 })
        : NodeEffect Nat Nat (NodeState Nat Nat)).run
        {}).map
        (fun result =>
          (
            result.1.commitIndex,
            result.1.retirementCompletedNodes config,
            retiredCommittedNodes result.1.committedLog
          ))
      = some (5, ∅, {1}) := by
  cbv

/-- Removing a node does not make its retirement completed in the same transaction. -/
theorem incomplete_retirement_disables_transaction
    : ((appendBatch config caps 0 initial
          [.transaction 4 { configuration := some {0, 2}, retiredCommitted := {1} }]).run
        {}).isNone
      = true := by
  cbv

/-- A pending retirement record cannot be duplicated by a later transaction. -/
theorem duplicate_retirement_disables_batch
    : ((appendBatch config caps 0 beforeRetirementRecord
          [combinedTransaction, .transaction 5 { retiredCommitted := {1} }]).run
        {}).isNone
      = true := by
  cbv

theorem unchanged_configuration_disables_transaction
    : ((appendBatch config caps 0 initial
          [.transaction 5 { configuration := some {0, 1} }]).run
        {}).isNone
      = true := by
  cbv

/-- A later invalid entry disables the whole batch, not just that entry. -/
theorem failing_batch_discards_outputs
    : ((appendBatch config caps 0 initial
          [
            .transaction 5 { configuration := some {0, 1, 2} },
            .transaction 6 { configuration := some ∅ }
          ]).run
        {}).isNone
      = true := by
  cbv

theorem signature_requires_prefix
    : ((appendEntry config caps 0 { initial with log := [] } .signature).run {}).isNone
      = true := by
  decide

end CCFRaft.Tests.AppendTransactions
