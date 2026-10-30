module

public import DisasterRecovery.Properties.Utils

import DisasterRecovery.Proofs.Local
import DisasterRecovery.Proofs.Model
import DisasterRecovery.Proofs.Witnesses

@[expose] public section

namespace DisasterRecovery.Properties

open Model.Local

-- Global invariants for all valid traces and corresponding witness

/-- In a valid trace, all `opening quorum` notifications are emitted by the same
node. -/
theorem quorum_opener_unique
    : forall (config : Model.Config) (trace : GlobalTrace),
      forall (firstStep secondStep : Nat) (firstOpener secondOpener : Location),
        (trace.Valid (Model.transitionSystem config)
          /\ Trace.NotificationAt config trace firstStep firstOpener (.opening .quorum)
          /\ Trace.NotificationAt config trace secondStep secondOpener (.opening .quorum))
        -> firstOpener = secondOpener := by
  exact Proofs.Model.quorum_opener_unique

/-- Witness: a valid trace exists with a step emitting `opening quorum`. -/
lemma quorum_opener_unique_witness
    : exists (config : Model.Config) (trace : GlobalTrace),
    exists (step : Nat) (opener : Location),
      trace.Valid (Model.transitionSystem config)
      /\ Trace.NotificationAt config trace step opener (.opening .quorum) := by
  exact Proofs.Witnesses.quorum_opener_unique_witness

/-- A quorum opener whose voters received their own gossip is up to date with a
quorum of recovered ledgers. -/
theorem quorum_open_preserves_commit
    : forall (config : Model.Config) (trace : GlobalTrace) (openedState : Model.State),
      forall (opener : Location) (openerState : NodeState),
        (trace.Valid (Model.transitionSystem config)
          /\ openedState ∈ trace
          /\ (opener, openerState) ∈ openedState.nodes
          /\ openerState.openKind = some .quorum
          /\ (forall voter, voter ∈ openerState.votes -> ReceivedOwnGossip trace voter))
        -> exists openerTxID,
            Model.recoveredTxID config opener = some openerTxID
            /\ UpToDateWithQuorum config openerTxID := by
  exact Proofs.Gossip.quorum_open_preserves_commit

/-- Witness: a valid trace and a state in it with a node with `openKind = quorum` whose
voters all satisfy `ReceivedOwnGossip` exist. -/
lemma quorum_open_preserves_commit_witness
    : exists (config : Model.Config) (trace : GlobalTrace) (openedState : Model.State),
    exists (opener : Location) (openerState : NodeState),
      trace.Valid (Model.transitionSystem config)
      /\ openedState ∈ trace
      /\ (opener, openerState) ∈ openedState.nodes
      /\ openerState.openKind = some .quorum
      /\ (forall voter, voter ∈ openerState.votes -> ReceivedOwnGossip trace voter) := by
  exact Proofs.Witnesses.quorum_open_preserves_commit_witness

/-- If every configured location has full gossip somewhere in a valid trace, every opener,
including failover openers, is up to date with a quorum of recovered ledgers. -/
theorem full_gossip_preserves_commit
    : forall (config : Model.Config) (trace : GlobalTrace)
              (gossipedState openedState : Model.State),
      forall (opener : Location) (openerState : NodeState),
        (trace.Valid (Model.transitionSystem config)
          /\ gossipedState ∈ trace
          /\ (forall node nodeState,
                node ∈ config.protocol.expectedLocations
                -> (node, nodeState) ∈ gossipedState.nodes
                -> forall gossip,
                    gossip ∈ nodeState.gossips <-> gossip ∈ config.recovered)
          /\ openedState ∈ trace
          /\ (opener, openerState) ∈ openedState.nodes
          /\ openerState.openKind.isSome = true)
        -> exists openerTxID,
            Model.recoveredTxID config opener = some openerTxID
            /\ UpToDateWithQuorum config openerTxID := by
  exact Proofs.Gossip.full_gossip_preserves_commit

/-- Witness: a valid trace with a full-gossip state and a state in it with a node with
`openKind = failover` exist. -/
lemma full_gossip_preserves_commit_witness
    : exists (config : Model.Config) (trace : GlobalTrace),
    exists (gossipedState openedState : Model.State),
    exists (opener : Location) (openerState : NodeState),
      trace.Valid (Model.transitionSystem config)
      /\ gossipedState ∈ trace
      /\ (forall node nodeState,
            node ∈ config.protocol.expectedLocations
            -> (node, nodeState) ∈ gossipedState.nodes
            -> forall gossip, gossip ∈ nodeState.gossips <-> gossip ∈ config.recovered)
      /\ openedState ∈ trace
      /\ (opener, openerState) ∈ openedState.nodes
      /\ openerState.openKind = some .failover := by
  exact Proofs.Witnesses.full_gossip_preserves_commit_witness

-- Local invariants of the step function: they hold for every node state,
-- not only reachable ones.

/-- A valid step receiving accepted gossip when `chosen` is set leaves the state
unchanged and notifies `rejected "gossip-frozen"`. -/
theorem gossip_freezes_after_choice
    : forall (config : Model.Config),
      forall localStep : LocalStep,
      forall (source : Location) (txid : TxID),
        ((Model.protocol config).ValidStep localStep
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

/-- A valid step receiving rejected gossip leaves the state unchanged and notifies
`rejected "quote-or-certificate"`. -/
theorem rejected_gossip_stutters
    : forall (config : Model.Config),
      forall localStep : LocalStep,
      forall (source : Location) (txid : TxID),
        ((Model.protocol config).ValidStep localStep
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

/-- A valid timeout or accepted-vote step from `voting` with at least `voteQuorum`
votes moves to `opening` with `openKind = quorum` and notifies `opening quorum`. -/
theorem quorum_advance_opens
    : forall (config : Model.Config),
      forall localStep : LocalStep,
        ((Model.protocol config).ValidStep localStep
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

/-- A valid timeout step with `phase` and `timeoutState` both `opening` only sets
`phase` to `open`, and notifies `completed`. -/
theorem aligned_opening_timeout_completes
    : forall (config : Model.Config),
      forall localStep : LocalStep,
        ((Model.protocol config).ValidStep localStep
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
