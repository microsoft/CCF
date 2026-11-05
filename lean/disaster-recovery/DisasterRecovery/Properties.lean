module

public import DisasterRecovery.Properties.Utils

import DisasterRecovery.Proofs.Local
import DisasterRecovery.Proofs.Model
import DisasterRecovery.Proofs.Witnesses

@[expose] public section

namespace DisasterRecovery.Properties

open Model.Local

-- Global invariants from reachable network states.

/-- All quorum-opening notifications along one reachable execution have the same emitter. -/
theorem quorum_opener_unique
    : forall (config : Model.Config) (start final : Model.State) (actions : List Model.Action)
    (firstOpener secondOpener : Location),
    ((Model.transitionSystem config).Reachable start
      /\ CCF.Execution.Run (Model.transitionSystem config) start actions final
      /\ NotificationDuring config start actions final firstOpener (.opening .quorum)
      /\ NotificationDuring config start actions final secondOpener (.opening .quorum))
    -> firstOpener = secondOpener := by
  exact Proofs.Model.quorum_opener_unique

/-- Witness: a valid trace exists with a step emitting `opening quorum`. -/
lemma quorum_opener_unique_witness
    : exists (config : Model.Config) (trace : GlobalTrace config),
    exists (step : Nat) (opener : Location),
      Trace.NotificationAt config trace step opener (.opening .quorum) := by
  exact Proofs.Witnesses.quorum_opener_unique_witness

/-- A reachable quorum opener whose voters receive own gossip in the same execution is fresh. -/
theorem quorum_open_preserves_commit
    : forall (config : Model.Config) (start final openedState : Model.State)
    (actions : List Model.Action) (opener : Location) (openerState : NodeState),
    ((Model.transitionSystem config).Reachable start
      /\ CCF.Execution.Run (Model.transitionSystem config) start actions final
      /\ CCF.Execution.Visits (Model.transitionSystem config) start actions openedState
      /\ (opener, openerState) ∈ openedState.nodes
      /\ openerState.openKind = some .quorum
      /\ (forall voter, voter ∈ openerState.votes
        -> ReceivedOwnGossipDuring config start actions voter))
    -> exists openerTxID,
      Model.recoveredTxID config opener = some openerTxID
      /\ UpToDateWithQuorum config openerTxID := by
  exact Proofs.Gossip.quorum_open_preserves_commit

/-- Witness: a valid trace and a state in it with a node with `openKind = quorum` whose
voters all satisfy `ReceivedOwnGossip` exist. -/
lemma quorum_open_preserves_commit_witness
    : exists
    (config : Model.Config) (trace : GlobalTrace config) (openedState : Model.State),
    exists (opener : Location) (openerState : NodeState),
      openedState ∈ trace
      /\ (opener, openerState) ∈ openedState.nodes
      /\ openerState.openKind = some .quorum
      /\ (forall voter, voter ∈ openerState.votes -> ReceivedOwnGossip trace voter) := by
  exact Proofs.Witnesses.quorum_open_preserves_commit_witness

/-- Full gossip and opening in the same reachable execution imply freshness, in either order. -/
theorem full_gossip_preserves_commit
    : forall (config : Model.Config) (start final gossipedState openedState : Model.State)
    (actions : List Model.Action) (opener : Location) (openerState : NodeState),
    ((Model.transitionSystem config).Reachable start
      /\ CCF.Execution.Run (Model.transitionSystem config) start actions final
      /\ CCF.Execution.Visits (Model.transitionSystem config) start actions gossipedState
      /\ (forall node nodeState, node ∈ config.protocol.expectedLocations
        -> (node, nodeState) ∈ gossipedState.nodes
        -> forall gossip, gossip ∈ nodeState.gossips <-> gossip ∈ config.recovered)
      /\ CCF.Execution.Visits (Model.transitionSystem config) start actions openedState
      /\ (opener, openerState) ∈ openedState.nodes
      /\ openerState.openKind.isSome = true)
    -> exists openerTxID,
      Model.recoveredTxID config opener = some openerTxID
      /\ UpToDateWithQuorum config openerTxID := by
  exact Proofs.Gossip.full_gossip_preserves_commit

/-- Witness: a valid trace with a full-gossip state and a state in it with a node with
`openKind = failover` exist. -/
lemma full_gossip_preserves_commit_witness
    : exists (config : Model.Config) (trace : GlobalTrace config),
    exists (gossipedState openedState : Model.State),
    exists (opener : Location) (openerState : NodeState),
      gossipedState ∈ trace
      /\ (forall node nodeState,
            node ∈ config.protocol.expectedLocations
            -> (node, nodeState) ∈ gossipedState.nodes
            -> forall gossip, gossip ∈ nodeState.gossips <-> gossip ∈ config.recovered)
      /\ openedState ∈ trace
      /\ (opener, openerState) ∈ openedState.nodes
      /\ openerState.openKind = some .failover := by
  exact Proofs.Witnesses.full_gossip_preserves_commit_witness

-- Local effects of enabled steps from reachable network states.

/-- A reachable delivery of accepted gossip after choice stutters and reports frozen gossip. -/
theorem gossip_freezes_after_choice
    : forall (config : Model.Config) (before after : Model.State) (action : Model.Action)
    (localStep : LocalStep) (source : Location) (txid : TxID),
    ((Model.transitionSystem config).Reachable before
      /\ NetworkStep config before action after localStep
      /\ localStep.action = .receiveGossip source txid .accepted
      /\ localStep.before.chosen.isSome = true)
    -> localStep.after = localStep.before
      /\ .rejected "gossip-frozen" ∈ localStep.effects.notifications := by
  exact Proofs.Local.gossip_freezes_after_choice

/-- Witness: a valid step exists that receives accepted gossip when `chosen` is set. -/
lemma gossip_freezes_after_choice_witness
    : exists (config : Model.Config),
    exists localStep : LocalStep,
    exists (source : Location) (txid : TxID),
      (Model.protocol config).ValidStep localStep
      /\ localStep.action = .receiveGossip source txid .accepted
      /\ localStep.before.chosen.isSome = true := by
  exact Proofs.Witnesses.gossip_freezes_after_choice_witness

/--
A reachable rejected-gossip step would stutter and report rejection.
This is vacuous in the current network model: `Model.receive` only constructs accepted events.
The underlying local proof and unchanged witness cover the rejected-event handler.
-/
theorem rejected_gossip_stutters
    : forall (config : Model.Config) (before after : Model.State) (action : Model.Action)
    (localStep : LocalStep) (source : Location) (txid : TxID),
    ((Model.transitionSystem config).Reachable before
      /\ NetworkStep config before action after localStep
      /\ localStep.action = .receiveGossip source txid .rejected)
    -> localStep.after = localStep.before
      /\ .rejected "quote-or-certificate" ∈ localStep.effects.notifications := by
  exact Proofs.Local.rejected_gossip_stutters

/-- Witness: a valid step exists that receives rejected gossip. -/
lemma rejected_gossip_stutters_witness
    : exists (config : Model.Config),
    exists localStep : LocalStep,
    exists (source : Location) (txid : TxID),
      (Model.protocol config).ValidStep localStep
      /\ localStep.action = .receiveGossip source txid .rejected := by
  exact Proofs.Witnesses.rejected_gossip_stutters_witness

/-- A reachable timeout or accepted vote with a voting quorum opens by quorum. -/
theorem quorum_advance_opens
    : forall (config : Model.Config) (before after : Model.State) (action : Model.Action)
    (localStep : LocalStep),
    ((Model.transitionSystem config).Reachable before
      /\ NetworkStep config before action after localStep
      /\ (localStep.action = .timeout
      \/ exists source, localStep.action = .receiveVote source .accepted)
      /\ localStep.before.phase = .voting
      /\ localStep.before.votes.length >= voteQuorum config.protocol)
    -> localStep.after.phase = .opening
      /\ localStep.after.openKind = some .quorum
      /\ .opening .quorum ∈ localStep.effects.notifications := by
  exact Proofs.Local.quorum_step_opens

/-- Witness: a valid timeout or accepted-vote step exists from `voting` with at
least `voteQuorum` votes. -/
lemma quorum_advance_opens_witness
    : exists (config : Model.Config),
    exists localStep : LocalStep,
      (Model.protocol config).ValidStep localStep
      /\ (localStep.action = .timeout
          \/ exists source, localStep.action = .receiveVote source .accepted)
      /\ localStep.before.phase = .voting
      /\ localStep.before.votes.length >= voteQuorum config.protocol := by
  exact Proofs.Witnesses.quorum_advance_opens_witness

/-- A reachable aligned opening timeout only changes the phase to open and completes. -/
theorem aligned_opening_timeout_completes
    : forall (config : Model.Config) (before after : Model.State) (action : Model.Action)
    (localStep : LocalStep),
    ((Model.transitionSystem config).Reachable before
      /\ NetworkStep config before action after localStep
      /\ localStep.action = .timeout
      /\ localStep.before.phase = .opening
      /\ localStep.before.timeoutState = .opening)
    -> localStep.after = { localStep.before with phase := .open }
      /\ .completed ∈ localStep.effects.notifications := by
  exact Proofs.Local.aligned_opening_timeout_completes

/-- Witness: a valid timeout step exists with `phase` and `timeoutState` both
`opening`. -/
lemma aligned_opening_timeout_completes_witness
    : exists (config : Model.Config),
    exists localStep : LocalStep,
      (Model.protocol config).ValidStep localStep
      /\ localStep.action = .timeout
      /\ localStep.before.phase = .opening
      /\ localStep.before.timeoutState = .opening := by
  exact Proofs.Witnesses.aligned_opening_timeout_completes_witness

end DisasterRecovery.Properties
