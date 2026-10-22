module

import all Init.Prelude
import all Lean.Data.Name
meta import CCF.Architecture

public import CCF.Architecture
public import DisasterRecovery.Properties

@[expose] public section

namespace DisasterRecovery.Tests.Architecture

open Lean

/--
error: Unknown identifier `undeclaredType`

Note: It is not possible to treat `undeclaredType` as an implicitly bound variable here because the `autoImplicit` option is set to `false`.
-/
#guard_msgs in
example (value : undeclaredType) := value

example
    : CCF.Architecture.allowedImport `DisasterRecovery `DisasterRecovery.Properties
        `DisasterRecovery.Model
      = true :=
  rfl

example
    : CCF.Architecture.allowedImport `DisasterRecovery `DisasterRecovery.Properties.Utils
        `CCF.Execution
      = true :=
  rfl

example
    : CCF.Architecture.allowedImport `DisasterRecovery `DisasterRecovery.Properties.Utils
        `DisasterRecovery.Proofs.Model
      = false :=
  rfl

example
    : CCF.Architecture.allowedImport `DisasterRecovery `DisasterRecovery.Properties
        `DisasterRecovery.Proof
      = false :=
  rfl

example
    : CCF.Architecture.allowedImport `DisasterRecovery `DisasterRecovery.Model.Local
        `DisasterRecovery.Properties.Utils
      = false :=
  rfl

example
    : CCF.Architecture.allowedImport `DisasterRecovery `CCF.MultiNodeTransitionSystem
        `DisasterRecovery.Model
      = false :=
  rfl

example
    : CCF.Architecture.allowedImport `DisasterRecovery `DisasterRecovery.Properties
        `DisasterRecovery
      = false :=
  rfl

run_cmd do
  let env ← getEnv
  for name in #[`DisasterRecovery.Model.Local.observe,
      `DisasterRecovery.Model.Local.transitionSystem,
      `DisasterRecovery.Model.Local.stateKey,
      `DisasterRecovery.Model.Local.phaseName,
      `DisasterRecovery.Model.Local.openKindName,
      `DisasterRecovery.Model.Local.receive,
      `CCF.MultiNodeTransitionSystem.runStep,
      `CCF.MultiNodeTransitionSystem.runLocal,
      `CCF.MultiNodeTransitionSystem.replaceNode,
      `DisasterRecovery.Model.Local.Result,
      `DisasterRecovery.Model.Config.active,
      `DisasterRecovery.Model.initial,
      `DisasterRecovery.Model.next,
      `DisasterRecovery.Model.nodeState,
      `DisasterRecovery.Model.Reachable,
      `DisasterRecovery.Properties.Reachable,
      `DisasterRecovery.Properties.History.History,
      `DisasterRecovery.Properties.ReachableWellFormed,
      `DisasterRecovery.Properties.ReachableQuorumInvariant,
      `DisasterRecovery.Properties.TraceWellFormed,
      `DisasterRecovery.Properties.TraceQuorumInvariant,
      `DisasterRecovery.Properties.QuorumTraceOpenerUnique,
      `DisasterRecovery.Properties.Helpers.WellFormed,
      `DisasterRecovery.Properties.Helpers.QuorumInvariant,
      `DisasterRecovery.Properties.Helpers.QuorumOpened,
      `DisasterRecovery.Properties.Helpers.TxID.EarlierThan,
      `DisasterRecovery.Properties.Helpers.DurableCommit,
      `DisasterRecovery.Properties.History.WellFormed,
      `DisasterRecovery.Properties.History.QuorumInvariant,
      `DisasterRecovery.Properties.History.OpeningValid,
      `DisasterRecovery.Properties.History.VotingSelection,
      `DisasterRecovery.Properties.History.SentAt,
      `DisasterRecovery.Properties.History.Sent,
      `DisasterRecovery.Properties.History.SentVote,
      `DisasterRecovery.Properties.History.QuorumOpened,
      `DisasterRecovery.Properties.History.FullGossipSelection,
      `DisasterRecovery.Properties.QuorumHistoryOpenerUnique,
      `CCF.Execution.History,
      `CCF.Execution.reachable_iff_history,
      `DisasterRecovery.Properties.ContainsRaftCommittable,
      `DisasterRecovery.Properties.RaftCommittable,
      `DisasterRecovery.Properties.TxIDAtOrAfter,
      `DisasterRecovery.Properties.FullGossipSelectionPreservesCommit,
      `CCF.Execution.Transition,
      `CCF.Execution.ValidSteps,
      `CCF.Execution.Trace.track,
      `CCF.Execution.Trace.final,
      `DisasterRecovery.Properties.Trace.OutputAt] do
    if env.contains name then
      throwError "Removed model/property API must not be reintroduced: {name}"
  for name in env.header.moduleNames do
    if #[`CCF.Global, `DisasterRecovery.Properties.Trace, `DisasterRecovery.Properties.History].contains name then
      throwError "Removed module must not be reintroduced: {name}"
  for error in CCF.Architecture.layeringErrors env `DisasterRecovery do
    throwError error

end DisasterRecovery.Tests.Architecture
