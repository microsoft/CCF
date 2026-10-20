module

import all Init.Prelude
import all Lean.Data.Name

public import DisasterRecovery.Properties
public import Lean

@[expose] public section

namespace DisasterRecovery.Tests.Architecture

open Lean

/--
error: Unknown identifier `undeclaredType`

Note: It is not possible to treat `undeclaredType` as an implicitly bound variable here because the `autoImplicit` option is set to `false`.
-/
#guard_msgs in
example (value : undeclaredType) := value

private def allowedImport (owner dependency : Name) : Bool :=
  if (`CCF).isPrefixOf owner then
    (`CCF).isPrefixOf dependency || !(`DisasterRecovery).isPrefixOf dependency
  else if !(`DisasterRecovery).isPrefixOf dependency then
    true
  else if (`DisasterRecovery.Model).isPrefixOf owner then
    (`CCF).isPrefixOf dependency || (`DisasterRecovery.Model).isPrefixOf dependency
  else if (`DisasterRecovery.Properties).isPrefixOf owner then
    (`CCF).isPrefixOf dependency
    || (`DisasterRecovery.Model).isPrefixOf dependency
    || (`DisasterRecovery.Properties).isPrefixOf dependency
  else
    true

example : allowedImport `DisasterRecovery.Properties `DisasterRecovery.Model = true := rfl

example : allowedImport `DisasterRecovery.Properties.Utils `CCF.Execution = true :=
  rfl

example
    : allowedImport `DisasterRecovery.Properties.Utils `DisasterRecovery.Proofs.Model
      = false :=
  rfl

example : allowedImport `DisasterRecovery.Properties `DisasterRecovery.Proof = false :=
  rfl

example
    : allowedImport `DisasterRecovery.Model.Local `DisasterRecovery.Properties.Utils
      = false :=
  rfl

example : allowedImport `CCF.MultiNodeTransitionSystem `DisasterRecovery.Model = false :=
  rfl

example : allowedImport `DisasterRecovery.Properties `DisasterRecovery = false := rfl

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
  let header := env.header
  for name in header.moduleNames do
    if #[`CCF.Global, `DisasterRecovery.Properties.Trace, `DisasterRecovery.Properties.History].contains name then
      throwError "Removed module must not be reintroduced: {name}"
    if (`DisasterRecovery.Proof).isPrefixOf name ||
        (`DisasterRecovery.Proofs).isPrefixOf name then
      throwError "Property definitions import proof module {name}"
  for (owner, data) in header.moduleNames.zip header.moduleData do
    for dependency in data.imports do
      unless allowedImport owner dependency.module do
        throwError "Forbidden model/property dependency: {owner} imports {dependency.module}"

end DisasterRecovery.Tests.Architecture
