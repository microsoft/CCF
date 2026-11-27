module

public import DisasterRecovery.Properties.Utils

import DisasterRecovery.Proofs.Local
import DisasterRecovery.Proofs.Deadlock
import DisasterRecovery.Proofs.Safety
import DisasterRecovery.Proofs.Witnesses
import DisasterRecovery.Proofs.GlobalWitnesses

@[expose] public section

namespace DisasterRecovery.Properties

open Model.Local

/-- Every reachable recovery state has an enabled action. -/
theorem deadlock_free
    : forall (config : Model.Config), (Model.transitionSystem config).DeadlockFree := by
  exact Proofs.Deadlock.deadlock_free

/-- Witness: every valid recovery configuration has a reachable initial state. -/
theorem deadlock_free_witness
    : forall (config : ValidConfig),
        exists (state : Model.State),
          (Model.transitionSystem config).Reachable state := by
  exact Proofs.Deadlock.deadlock_free_witness

-- Global invariants for all valid behaviours and corresponding witness

/-- In a valid behaviour, all `opening quorum` notifications are emitted by the same
node. -/
theorem quorum_opener_unique
    : forall (config : Model.Config) (behaviour : Behaviour config),
      forall (firstStep secondStep : Nat) (firstOpener secondOpener : Location),
        (Behaviour.NotificationAt config behaviour firstStep firstOpener
            (.opening .quorum)
          /\ Behaviour.NotificationAt config behaviour secondStep secondOpener
              (.opening .quorum))
        -> firstOpener = secondOpener := by
  exact Proofs.Model.quorum_opener_unique

/-- Witness: for every valid configuration, a valid behaviour exists with a step emitting
`opening quorum`. -/
theorem quorum_opener_unique_witness
    : forall (config : ValidConfig),
        exists (behaviour : Behaviour config),
        exists (step : Nat) (opener : Location),
          Behaviour.NotificationAt config behaviour step opener (.opening .quorum) := by
  exact Proofs.GlobalWitnesses.quorum_opener_unique_witness

/-- A quorum opener whose voters received their own gossip is up to date with a
quorum of recovered ledgers. -/
theorem quorum_open_preserves_commit
    : forall (config : Model.Config) (behaviour : Behaviour config)
              (openedState : Model.State),
      forall (opener : Location) (openerState : NodeState),
        (openedState ∈ behaviour
          /\ (opener, openerState) ∈ openedState.nodes
          /\ openerState.openKind = some .quorum
          /\ (forall voter,
                voter ∈ openerState.votes -> ReceivedOwnGossip behaviour voter))
        -> exists openerTxID,
            Model.recoveredTxID config opener = some openerTxID
            /\ UpToDateWithQuorum config openerTxID := by
  exact Proofs.Gossip.quorum_open_preserves_commit

/-- Witness: for every valid configuration, a valid behaviour and a state in it with a node with
`openKind = quorum` whose voters all satisfy `ReceivedOwnGossip` exist. -/
theorem quorum_open_preserves_commit_witness
    : forall (config : ValidConfig),
        exists (behaviour : Behaviour config) (openedState : Model.State),
        exists (opener : Location) (openerState : NodeState),
          openedState ∈ behaviour
          /\ (opener, openerState) ∈ openedState.nodes
          /\ openerState.openKind = some .quorum
          /\ (forall voter,
                voter ∈ openerState.votes -> ReceivedOwnGossip behaviour voter) := by
  exact Proofs.GlobalWitnesses.quorum_open_preserves_commit_witness

/-- If every configured location has full gossip somewhere in a valid behaviour, every opener,
including failover openers, is up to date with a quorum of recovered ledgers. -/
theorem full_gossip_preserves_commit
    : forall (config : Model.Config) (behaviour : Behaviour config)
              (gossipedState openedState : Model.State),
      forall (opener : Location) (openerState : NodeState),
        (gossipedState ∈ behaviour
          /\ (forall node nodeState,
                node ∈ config.protocol.expectedLocations
                -> (node, nodeState) ∈ gossipedState.nodes
                -> forall gossip,
                    gossip ∈ nodeState.gossips <-> gossip ∈ config.recovered)
          /\ openedState ∈ behaviour
          /\ (opener, openerState) ∈ openedState.nodes
          /\ openerState.openKind.isSome = true)
        -> exists openerTxID,
            Model.recoveredTxID config opener = some openerTxID
            /\ UpToDateWithQuorum config openerTxID := by
  exact Proofs.Gossip.full_gossip_preserves_commit

/-- Witness: for every valid configuration with at least two locations, a valid behaviour with a
full-gossip state and a state in it with a node with `openKind = failover` exist. -/
theorem full_gossip_preserves_commit_witness
    : forall (config : ValidConfig),
        2 <= config.val.protocol.expectedLocations.length
        -> exists (behaviour : Behaviour config),
        exists (gossipedState openedState : Model.State),
        exists (opener : Location) (openerState : NodeState),
          gossipedState ∈ behaviour
          /\ (forall node nodeState,
                node ∈ config.val.protocol.expectedLocations
                -> (node, nodeState) ∈ gossipedState.nodes
                -> forall gossip,
                    gossip ∈ nodeState.gossips <-> gossip ∈ config.val.recovered)
          /\ openedState ∈ behaviour
          /\ (opener, openerState) ∈ openedState.nodes
          /\ openerState.openKind = some .failover := by
  exact Proofs.GlobalWitnesses.full_gossip_preserves_commit_witness

-- Local invariants of running and committing a transaction: they hold for every node
-- state, not only reachable ones.

/-- A valid step running the transaction of accepted gossip when `chosen` is set leaves
the state unchanged and notifies `rejected "gossip-frozen"`. -/
theorem gossip_freezes_after_choice
    : forall (config : Model.Config),
      forall localStep : LocalStep,
      forall (source : Location) (txid : TxID),
        ((Model.protocol config).ValidStep localStep
          /\ localStep.action = .run (.receiveGossip source txid .accepted)
          /\ localStep.before.chosen.isSome = true)
        -> localStep.after = localStep.before
            /\ .rejected "gossip-frozen" ∈ localStep.effects.notifications := by
  exact Proofs.Local.gossip_freezes_after_choice

/-- Witness: for every valid configuration, a valid step exists that runs the transaction
of accepted gossip when `chosen` is set. -/
theorem gossip_freezes_after_choice_witness
    : forall (config : ValidConfig),
        exists localStep : LocalStep,
        exists (source : Location) (txid : TxID),
          (Model.protocol config).ValidStep localStep
          /\ localStep.action = .run (.receiveGossip source txid .accepted)
          /\ localStep.before.chosen.isSome = true := by
  exact Proofs.Witnesses.gossip_freezes_after_choice_witness

/-- A valid step running the transaction of rejected gossip leaves the state unchanged
and notifies `rejected "quote-or-certificate"`. -/
theorem rejected_gossip_stutters
    : forall (config : Model.Config),
      forall localStep : LocalStep,
      forall (source : Location) (txid : TxID),
        ((Model.protocol config).ValidStep localStep
          /\ localStep.action = .run (.receiveGossip source txid .rejected))
        -> localStep.after = localStep.before
            /\ .rejected "quote-or-certificate" ∈ localStep.effects.notifications := by
  exact Proofs.Local.rejected_gossip_stutters

/-- Witness: for every valid configuration, a valid step exists that runs the transaction
of rejected gossip. -/
theorem rejected_gossip_stutters_witness
    : forall (config : ValidConfig),
        exists localStep : LocalStep,
        exists (source : Location) (txid : TxID),
          (Model.protocol config).ValidStep localStep
          /\ localStep.action = .run (.receiveGossip source txid .rejected) := by
  exact Proofs.Witnesses.rejected_gossip_stutters_witness

/-- A valid step committing the transaction of a timeout or an accepted vote, from
`voting` with at least `voteQuorum` votes in a store with one cell for each key, moves
to `opening` with `openKind = quorum` and notifies `opening quorum`. -/
theorem quorum_advance_opens
    : forall (config : Model.Config),
      forall localStep : LocalStep,
      forall (index : Nat) (attempt : Attempt),
        ((Model.protocol config).ValidStep localStep
          /\ localStep.action = .commit index
          /\ Commits config localStep.before index attempt
          /\ (attempt.event = .timeout
              \/ exists source, attempt.event = .receiveVote source .accepted)
          /\ (localStep.before.store.map Prod.fst).Nodup
          /\ localStep.before.phase = .voting
          /\ localStep.before.votes.length >= voteQuorum config.protocol)
        -> localStep.after.phase = .opening
            /\ localStep.after.openKind = some .quorum
            /\ .opening .quorum ∈ localStep.effects.notifications := by
  exact Proofs.Local.quorum_advance_opens

/-- Witness: for every valid configuration, a valid step exists that commits the
transaction of a timeout or an accepted vote, from `voting` with at least `voteQuorum`
votes in a store with one cell for each key. -/
theorem quorum_advance_opens_witness
    : forall (config : ValidConfig),
        exists localStep : LocalStep,
        exists (index : Nat) (attempt : Attempt),
          (Model.protocol config).ValidStep localStep
          /\ localStep.action = .commit index
          /\ Commits config localStep.before index attempt
          /\ (attempt.event = .timeout
              \/ exists source, attempt.event = .receiveVote source .accepted)
          /\ (localStep.before.store.map Prod.fst).Nodup
          /\ localStep.before.phase = .voting
          /\ localStep.before.votes.length >= voteQuorum config.val.protocol := by
  exact Proofs.Witnesses.quorum_advance_opens_witness

/-- A valid step committing the transaction of a timeout with `phase` and `timeoutState`
both `opening` only writes `open` to the `phase` table, and notifies `completed`. -/
theorem aligned_opening_timeout_completes
    : forall (config : Model.Config),
      forall localStep : LocalStep,
      forall (index : Nat) (attempt : Attempt),
        ((Model.protocol config).ValidStep localStep
          /\ localStep.action = .commit index
          /\ Commits config localStep.before index attempt
          /\ attempt.event = .timeout
          /\ localStep.before.phase = .opening
          /\ localStep.before.timeoutState = .opening)
        -> localStep.after
              = {
                localStep.before with
                  store :=
                    CCF.OCC.publish localStep.before.store (localStep.before.version + 1)
                      [((.phase, none), some (.phase .open))]
                  version := localStep.before.version + 1
                  pending := localStep.before.pending.eraseIdx index
              }
            /\ .completed ∈ localStep.effects.notifications := by
  exact Proofs.Local.aligned_opening_timeout_completes

/-- Witness: for every valid configuration, a valid step exists that commits the
transaction of a timeout with `phase` and `timeoutState` both `opening`. -/
theorem aligned_opening_timeout_completes_witness
    : forall (config : ValidConfig),
        exists localStep : LocalStep,
        exists (index : Nat) (attempt : Attempt),
          (Model.protocol config).ValidStep localStep
          /\ localStep.action = .commit index
          /\ Commits config localStep.before index attempt
          /\ attempt.event = .timeout
          /\ localStep.before.phase = .opening
          /\ localStep.before.timeoutState = .opening := by
  exact Proofs.Witnesses.aligned_opening_timeout_completes_witness

end DisasterRecovery.Properties
