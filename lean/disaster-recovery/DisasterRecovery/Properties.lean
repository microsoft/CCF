module

public import DisasterRecovery.Properties.Utils
public import CCF.Witnessed

import DisasterRecovery.Proofs.Claims
import DisasterRecovery.Proofs.Deadlock
import DisasterRecovery.Proofs.Safety
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

-- Global invariants for all valid traces and corresponding witness

/-- In a valid trace, all `opening quorum` notifications are emitted by the same
node.
Witness: for every valid configuration, a valid trace exists with a step emitting
`opening quorum`. -/
theorem quorum_opener_unique
    : forall (config : Model.Config),
        config.Valid
        -> witnessed% forall (trace : GlobalTrace config) (firstStep secondStep : Nat)
                              (firstOpener secondOpener : Location),
                        {
                          pre :=
                            Trace.NotificationAt config trace firstStep firstOpener
                              (.opening .quorum)
                            /\ Trace.NotificationAt config trace secondStep secondOpener
                                (.opening .quorum)
                          post := firstOpener = secondOpener
                        } := by
  exact Proofs.Claims.quorum_opener_unique

/-- A quorum opener whose voters received their own gossip is up to date with a
quorum of recovered ledgers.
Witness: for every valid configuration, a valid trace and a state in it with a node with
`openKind = quorum` whose voters all satisfy `ReceivedOwnGossip` exist. -/
theorem quorum_open_preserves_commit
    : forall (config : Model.Config),
        config.Valid
        -> witnessed% forall (trace : GlobalTrace config) (openedState : Model.State)
                              (opener : Location) (openerState : NodeState),
                        {
                          pre :=
                            openedState ∈ trace
                            /\ (opener, openerState) ∈ openedState.nodes
                            /\ openerState.openKind = some .quorum
                            /\ (forall voter,
                                  voter ∈ openerState.votes
                                  -> ReceivedOwnGossip trace voter)
                          post :=
                            exists openerTxID,
                              Model.recoveredTxID config opener = some openerTxID
                              /\ UpToDateWithQuorum config openerTxID
                        } := by
  exact Proofs.Claims.quorum_open_preserves_commit

/-- If every configured location has full gossip somewhere in a valid trace, every opener,
including failover openers, is up to date with a quorum of recovered ledgers. -/
theorem full_gossip_preserves_commit
    : forall (config : Model.Config) (trace : GlobalTrace config)
              (gossipedState openedState : Model.State),
      forall (opener : Location) (openerState : NodeState),
        (gossipedState ∈ trace
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

/-- Witness: for every valid configuration with at least two locations, a valid trace with a
full-gossip state and a state in it with a node with `openKind = failover` exist. -/
theorem full_gossip_preserves_commit_witness
    : forall (config : ValidConfig),
        2 <= config.val.protocol.expectedLocations.length
        -> exists (trace : GlobalTrace config),
        exists (gossipedState openedState : Model.State),
        exists (opener : Location) (openerState : NodeState),
          gossipedState ∈ trace
          /\ (forall node nodeState,
                node ∈ config.val.protocol.expectedLocations
                -> (node, nodeState) ∈ gossipedState.nodes
                -> forall gossip,
                    gossip ∈ nodeState.gossips <-> gossip ∈ config.val.recovered)
          /\ openedState ∈ trace
          /\ (opener, openerState) ∈ openedState.nodes
          /\ openerState.openKind = some .failover := by
  exact Proofs.GlobalWitnesses.full_gossip_preserves_commit_witness

-- Local invariants of the step function: they hold for every node state,
-- not only reachable ones.

/-- A valid step receiving accepted gossip when `chosen` is set leaves the state
unchanged and notifies `rejected "gossip-frozen"`.
Witness: for every valid configuration, such a step exists. -/
theorem gossip_freezes_after_choice
    : forall (config : Model.Config),
        config.Valid
        -> witnessed% forall (localStep : LocalStep) (source : Location) (txid : TxID),
                        {
                          pre :=
                            (Model.protocol config).ValidStep localStep
                            /\ localStep.action = .receiveGossip source txid .accepted
                            /\ localStep.before.chosen.isSome = true
                          post :=
                            localStep.after = localStep.before
                            /\ .rejected "gossip-frozen" ∈ localStep.effects.notifications
                        } := by
  exact Proofs.Claims.gossip_freezes_after_choice

/-- A valid step receiving rejected gossip leaves the state unchanged and notifies
`rejected "quote-or-certificate"`.
Witness: for every valid configuration, such a step exists. -/
theorem rejected_gossip_stutters
    : forall (config : Model.Config),
        config.Valid
        -> witnessed% forall (localStep : LocalStep) (source : Location) (txid : TxID),
                        {
                          pre :=
                            (Model.protocol config).ValidStep localStep
                            /\ localStep.action = .receiveGossip source txid .rejected
                          post :=
                            localStep.after = localStep.before
                            /\ .rejected "quote-or-certificate"
                                ∈ localStep.effects.notifications
                        } := by
  exact Proofs.Claims.rejected_gossip_stutters

/-- A valid timeout or accepted-vote step from `voting` with at least `voteQuorum`
votes moves to `opening` with `openKind = quorum` and notifies `opening quorum`.
Witness: for every valid configuration, such a step exists. -/
theorem quorum_advance_opens
    : forall (config : Model.Config),
        config.Valid
        -> witnessed% forall (localStep : LocalStep),
                        {
                          pre :=
                            (Model.protocol config).ValidStep localStep
                            /\ (localStep.action = .timeout
                                \/ exists source,
                                    localStep.action = .receiveVote source .accepted)
                            /\ localStep.before.phase = .voting
                            /\ localStep.before.votes.length >= voteQuorum config.protocol
                          post :=
                            localStep.after.phase = .opening
                            /\ localStep.after.openKind = some .quorum
                            /\ .opening .quorum ∈ localStep.effects.notifications
                        } := by
  exact Proofs.Claims.quorum_advance_opens

/-- A valid timeout step with `phase` and `timeoutState` both `opening` only sets
`phase` to `open`, and notifies `completed`.
Witness: for every valid configuration, such a step exists. -/
theorem aligned_opening_timeout_completes
    : forall (config : Model.Config),
        config.Valid
        -> witnessed% forall (localStep : LocalStep),
                        {
                          pre :=
                            (Model.protocol config).ValidStep localStep
                            /\ localStep.action = .timeout
                            /\ localStep.before.phase = .opening
                            /\ localStep.before.timeoutState = .opening
                          post :=
                            localStep.after = { localStep.before with phase := .open }
                            /\ .completed ∈ localStep.effects.notifications
                        } := by
  exact Proofs.Claims.aligned_opening_timeout_completes

end DisasterRecovery.Properties
