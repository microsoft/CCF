import DisasterRecovery.Properties.Utils

namespace DisasterRecovery.Properties

open Model.Local

-- Global invariants for all valid traces and corresponding witness

/-- In a valid trace, all `opening quorum` notifications are emitted by the same
node. -/
def QuorumOpenerUnique : Prop :=
  forall (config : Model.Config) (trace : GlobalTrace),
  forall (firstStep secondStep : Nat) (firstOpener secondOpener : Location),
    (trace.Valid (Model.transitionSystem config)
      /\ Trace.NotificationAt config trace firstStep firstOpener (.opening .quorum)
      /\ Trace.NotificationAt config trace secondStep secondOpener (.opening .quorum))
    -> firstOpener = secondOpener

/-- Witness: a valid trace exists with a step emitting `opening quorum`. -/
def QuorumOpenerUniqueWitness : Prop :=
  exists (config : Model.Config) (trace : GlobalTrace) (step : Nat) (opener : Location),
    trace.Valid (Model.transitionSystem config)
    /\ Trace.NotificationAt config trace step opener (.opening .quorum)

/-- A quorum opener whose voters received their own gossip is up to date with a
quorum of recovered ledgers. -/
def QuorumOpenPreservesCommit : Prop :=
  forall (config : Model.Config) (trace : GlobalTrace) (openedState : Model.State),
  forall (opener : Location) (openerState : NodeState),
    (trace.Valid (Model.transitionSystem config)
      /\ openedState ∈ trace.states
      /\ (opener, openerState) ∈ openedState.nodes
      /\ openerState.openKind = some .quorum
      /\ (forall voter, voter ∈ openerState.votes -> ReceivedOwnGossip trace voter))
    -> exists openerTxID,
        Model.recoveredTxID config opener = some openerTxID /\ UpToDateWithQuorum config openerTxID

/-- Witness: a valid trace and a state in it with a node with `openKind = quorum` whose
voters all satisfy `ReceivedOwnGossip` exist. -/
def QuorumOpenPreservesCommitWitness : Prop :=
  exists (config : Model.Config) (trace : GlobalTrace) (openedState : Model.State),
  exists (opener : Location) (openerState : NodeState),
    trace.Valid (Model.transitionSystem config)
    /\ openedState ∈ trace.states
    /\ (opener, openerState) ∈ openedState.nodes
    /\ openerState.openKind = some .quorum
    /\ (forall voter, voter ∈ openerState.votes -> ReceivedOwnGossip trace voter)

/-- If every node has full gossip somewhere in a valid trace, every opener,
including failover openers, is up to date with a quorum of recovered ledgers. -/
def FullGossipPreservesCommit : Prop :=
  forall (config : Model.Config) (trace : GlobalTrace) (gossipedState openedState : Model.State),
  forall (opener : Location) (openerState : NodeState),
    (trace.Valid (Model.transitionSystem config)
      /\ gossipedState ∈ trace.states
      /\ (forall node nodeState,
            (node, nodeState) ∈ gossipedState.nodes
            -> forall gossip, gossip ∈ nodeState.gossips <-> gossip ∈ config.recovered)
      /\ openedState ∈ trace.states
      /\ (opener, openerState) ∈ openedState.nodes
      /\ openerState.openKind.isSome = true)
    -> exists openerTxID,
        Model.recoveredTxID config opener = some openerTxID /\ UpToDateWithQuorum config openerTxID

/-- Witness: a valid trace with a full-gossip state and a state in it with a node with
`openKind = failover` exist. -/
def FullGossipPreservesCommitWitness : Prop :=
  exists (config : Model.Config) (trace : GlobalTrace) (gossipedState openedState : Model.State),
  exists (opener : Location) (openerState : NodeState),
    trace.Valid (Model.transitionSystem config)
    /\ gossipedState ∈ trace.states
    /\ (forall node nodeState,
          (node, nodeState) ∈ gossipedState.nodes
          -> forall gossip, gossip ∈ nodeState.gossips <-> gossip ∈ config.recovered)
    /\ openedState ∈ trace.states
    /\ (opener, openerState) ∈ openedState.nodes
    /\ openerState.openKind = some .failover

-- Local invariants of the step function: they hold for every node state,
-- not only reachable ones.

/-- A valid step receiving accepted gossip when `chosen` is set leaves the state
unchanged and notifies `rejected "gossip-frozen"`. -/
def GossipFreezesAfterChoice : Prop :=
  forall (config : Model.Config),
  forall localStep : LocalStep,
  forall (source : Location) (txid : TxID),
    ((Model.protocol config).ValidStep localStep
      /\ localStep.action = .receiveGossip source txid .accepted
      /\ localStep.before.chosen.isSome = true)
    -> localStep.after = localStep.before
        /\ .rejected "gossip-frozen" ∈ localStep.effects.notifications

/-- Witness: a valid step exists that receives accepted gossip when `chosen` is set. -/
def GossipFreezesAfterChoiceWitness : Prop :=
  exists (config : Model.Config),
  exists localStep : LocalStep,
  exists (source : Location) (txid : TxID),
    (Model.protocol config).ValidStep localStep
    /\ localStep.action = .receiveGossip source txid .accepted
    /\ localStep.before.chosen.isSome = true

/-- A valid step receiving rejected gossip leaves the state unchanged and notifies
`rejected "quote-or-certificate"`. -/
def RejectedGossipStutters : Prop :=
  forall (config : Model.Config),
  forall localStep : LocalStep,
  forall (source : Location) (txid : TxID),
    ((Model.protocol config).ValidStep localStep
      /\ localStep.action = .receiveGossip source txid .rejected)
    -> localStep.after = localStep.before
        /\ .rejected "quote-or-certificate" ∈ localStep.effects.notifications

/-- Witness: a valid step exists that receives rejected gossip. -/
def RejectedGossipStuttersWitness : Prop :=
  exists (config : Model.Config),
  exists localStep : LocalStep,
  exists (source : Location) (txid : TxID),
    (Model.protocol config).ValidStep localStep
    /\ localStep.action = .receiveGossip source txid .rejected

/-- A valid timeout or accepted-vote step from `voting` with at least `voteQuorum`
votes moves to `opening` with `openKind = quorum` and notifies `opening quorum`. -/
def QuorumAdvanceOpens : Prop :=
  forall (config : Model.Config),
  forall localStep : LocalStep,
    ((Model.protocol config).ValidStep localStep
      /\ (localStep.action = .timeout
          \/ exists source, localStep.action = .receiveVote source .accepted)
      /\ localStep.before.phase = .voting
      /\ localStep.before.votes.length >= voteQuorum config.protocol)
    -> localStep.after.phase = .opening
        /\ localStep.after.openKind = some .quorum
        /\ .opening .quorum ∈ localStep.effects.notifications

/-- Witness: a valid timeout or accepted-vote step exists from `voting` with at
least `voteQuorum` votes. -/
def QuorumAdvanceOpensWitness : Prop :=
  exists (config : Model.Config),
  exists localStep : LocalStep,
    (Model.protocol config).ValidStep localStep
    /\ (localStep.action = .timeout
        \/ exists source, localStep.action = .receiveVote source .accepted)
    /\ localStep.before.phase = .voting
    /\ localStep.before.votes.length >= voteQuorum config.protocol

/-- A valid timeout step with `phase` and `timeoutState` both `opening` only sets
`phase` to `open`, and notifies `completed`. -/
def AlignedOpeningTimeoutCompletes : Prop :=
  forall (config : Model.Config),
  forall localStep : LocalStep,
    ((Model.protocol config).ValidStep localStep
      /\ localStep.action = .timeout
      /\ localStep.before.phase = .opening
      /\ localStep.before.timeoutState = .opening)
    -> localStep.after = { localStep.before with phase := .open }
        /\ .completed ∈ localStep.effects.notifications

/-- Witness: a valid timeout step exists with `phase` and `timeoutState` both
`opening`. -/
def AlignedOpeningTimeoutCompletesWitness : Prop :=
  exists (config : Model.Config),
  exists localStep : LocalStep,
    (Model.protocol config).ValidStep localStep
    /\ localStep.action = .timeout
    /\ localStep.before.phase = .opening
    /\ localStep.before.timeoutState = .opening

end DisasterRecovery.Properties
