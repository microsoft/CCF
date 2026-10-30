module

public import DisasterRecovery.Properties.Utils
public import DisasterRecovery.Proofs.History
public import DisasterRecovery.Proofs.Gossip

@[expose] public section

namespace DisasterRecovery.Proofs.Model

lemma quorum_opener_unique
    : forall (config : Model.Config) (trace : Properties.GlobalTrace),
      forall (firstStep secondStep : Nat)
              (firstOpener secondOpener : Model.Local.Location),
        (trace.Valid (Model.transitionSystem config)
          /\ Properties.Trace.NotificationAt config trace firstStep firstOpener
              (.opening .quorum)
          /\ Properties.Trace.NotificationAt config trace secondStep secondOpener
              (.opening .quorum))
        -> firstOpener = secondOpener := by
  rintro config trace firstStep secondStep firstOpener secondOpener ⟨valid, first, second⟩
  obtain ⟨_, _, firstFound, _⟩ := Observed.notification_opening_state first
  obtain ⟨_, _, secondFound, _⟩ := Observed.notification_opening_state second
  obtain ⟨ghost, linked⟩ := History.history_correspondence trace valid
    (Trace.max_isSome (Option.isSome_iff_exists.mpr ⟨_, firstFound⟩)
      (Option.isSome_iff_exists.mpr ⟨_, secondFound⟩))
  obtain ⟨firstState, firstMember, firstThreshold⟩ :=
    Gossip.quorum_notification_final_votes valid linked (le_max_left _ _) first
  obtain ⟨secondState, secondMember, secondThreshold⟩ :=
    Gossip.quorum_notification_final_votes valid linked (le_max_right _ _) second
  exact Observed.current_quorum_unique_of_thresholds linked.reachable
    (firstOpener, firstState) (secondOpener, secondState)
    firstMember secondMember firstThreshold secondThreshold

lemma quorum_open_preserves_commit
    : forall (config : Model.Config) (trace : Properties.GlobalTrace)
              (openedState : Model.State),
      forall (opener : Model.Local.Location) (openerState : Model.Local.NodeState),
        (trace.Valid (Model.transitionSystem config)
          /\ openedState ∈ trace
          /\ (opener, openerState) ∈ openedState.nodes
          /\ openerState.openKind = some .quorum
          /\ (forall voter,
                voter ∈ openerState.votes -> Properties.ReceivedOwnGossip trace voter))
        -> exists openerTxID,
            Model.recoveredTxID config opener = some openerTxID
            /\ Properties.UpToDateWithQuorum config openerTxID :=
  Gossip.quorum_open_preserves_commit

lemma full_gossip_preserves_commit
    : forall (config : Model.Config) (trace : Properties.GlobalTrace)
              (gossipedState openedState : Model.State),
      forall (opener : Model.Local.Location) (openerState : Model.Local.NodeState),
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
            /\ Properties.UpToDateWithQuorum config openerTxID :=
  Gossip.full_gossip_preserves_commit

end DisasterRecovery.Proofs.Model
