module

public import DisasterRecovery.Properties

@[expose] public section

namespace DisasterRecovery.Tests.Witnesses

open Model.Local

example (config : Properties.ValidConfig)
    : exists (state : Model.State) (action : Model.Action) (nextState : Model.State),
        (Model.transitionSystem config).Reachable state
        /\ (Model.transitionSystem config).step state action = some nextState := by
  obtain ⟨state, reachable⟩ := Properties.deadlock_free_witness config
  obtain ⟨action, nextState, enabled⟩ := Properties.deadlock_free config state reachable
  exact ⟨state, action, nextState, reachable, enabled⟩

example (config : Properties.ValidConfig)
    : exists (behaviour : Properties.Behaviour config) (step : Nat) (opener : Location),
        Properties.Behaviour.NotificationAt config behaviour step opener
          (.opening .quorum)
        /\ opener = opener := by
  obtain ⟨behaviour, step, opener, notified⟩ := Properties.quorum_opener_unique_witness config
  exact ⟨behaviour, step, opener, notified,
    Properties.quorum_opener_unique config behaviour step step opener opener ⟨notified, notified⟩⟩

example (config : Properties.ValidConfig)
    : exists (opener : Location) (txid : TxID),
        Model.recoveredTxID config opener = some txid
        /\ Properties.UpToDateWithQuorum config txid := by
  obtain ⟨behaviour, openedState, opener, openerState, opened, present, kind, own⟩ :=
    Properties.quorum_open_preserves_commit_witness config
  obtain ⟨txid, recovered, upToDate⟩ :=
    Properties.quorum_open_preserves_commit config behaviour openedState opener openerState
      ⟨opened, present, kind, own⟩
  exact ⟨opener, txid, recovered, upToDate⟩

example (config : Properties.ValidConfig)
    (multiple : 2 <= config.val.protocol.expectedLocations.length)
    : exists (opener : Location) (txid : TxID),
        Model.recoveredTxID config opener = some txid
        /\ Properties.UpToDateWithQuorum config txid := by
  obtain ⟨behaviour, gossipedState, openedState, opener, openerState,
    gossiped, full, opened, present, kind⟩ := Properties.full_gossip_preserves_commit_witness config multiple
  obtain ⟨txid, recovered, upToDate⟩ :=
    Properties.full_gossip_preserves_commit config behaviour gossipedState openedState opener openerState
      ⟨gossiped, full, opened, present, by simp [kind]⟩
  exact ⟨opener, txid, recovered, upToDate⟩

example (config : Properties.ValidConfig)
    : exists localStep : Properties.LocalStep,
        localStep.after = localStep.before
        /\ .rejected "gossip-frozen" ∈ localStep.effects.notifications := by
  obtain ⟨localStep, source, txid, valid, action, chosen⟩ :=
    Properties.gossip_freezes_after_choice_witness config
  exact ⟨localStep,
    Properties.gossip_freezes_after_choice config localStep source txid ⟨valid, action, chosen⟩⟩

example (config : Properties.ValidConfig)
    : exists localStep : Properties.LocalStep,
        localStep.after = localStep.before
        /\ .rejected "quote-or-certificate" ∈ localStep.effects.notifications := by
  obtain ⟨localStep, source, txid, valid, action⟩ := Properties.rejected_gossip_stutters_witness config
  exact ⟨localStep,
    Properties.rejected_gossip_stutters config localStep source txid ⟨valid, action⟩⟩

example (config : Properties.ValidConfig)
    : exists localStep : Properties.LocalStep,
        localStep.after.phase = .opening
        /\ localStep.after.openKind = some .quorum
        /\ .opening .quorum ∈ localStep.effects.notifications := by
  obtain ⟨s, i, a, premises⟩ := Properties.quorum_advance_opens_witness config
  exact ⟨s, Properties.quorum_advance_opens config s i a premises⟩

example (config : Properties.ValidConfig)
    : exists (s : Properties.LocalStep) (i : Nat),
        s.after
          = {
            s.before with
              store :=
                CCF.OCC.publish s.before.store (s.before.version + 1)
                  [((.phase, none), some (.phase .open))]
              version := s.before.version + 1
              pending := s.before.pending.eraseIdx i
          }
        /\ .completed ∈ s.effects.notifications := by
  obtain ⟨s, i, a, premises⟩ := Properties.aligned_opening_timeout_completes_witness config
  exact ⟨s, i, Properties.aligned_opening_timeout_completes config s i a premises⟩

end DisasterRecovery.Tests.Witnesses
