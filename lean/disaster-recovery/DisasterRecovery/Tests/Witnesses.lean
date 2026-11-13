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
    : exists (trace : Properties.GlobalTrace config) (step : Nat) (opener : Location),
        Properties.Trace.NotificationAt config trace step opener (.opening .quorum)
        /\ opener = opener := by
  obtain ⟨trace, step, _, opener, _, notified, _⟩ :=
    (Properties.quorum_opener_unique config config.property).witness
  exact ⟨trace, step, opener, notified,
    (Properties.quorum_opener_unique config config.property).safety trace step step opener opener
      ⟨notified, notified⟩⟩

example (config : Properties.ValidConfig)
    : exists (opener : Location) (txid : TxID),
        Model.recoveredTxID config opener = some txid
        /\ Properties.UpToDateWithQuorum config txid := by
  obtain ⟨trace, openedState, opener, openerState, opened, present, kind, own⟩ :=
    (Properties.quorum_open_preserves_commit config config.property).witness
  obtain ⟨txid, recovered, upToDate⟩ :=
    (Properties.quorum_open_preserves_commit config config.property).safety trace openedState
      opener openerState ⟨opened, present, kind, own⟩
  exact ⟨opener, txid, recovered, upToDate⟩

example (config : Properties.ValidConfig)
    (multiple : 2 <= config.val.protocol.expectedLocations.length)
    : exists (opener : Location) (txid : TxID),
        Model.recoveredTxID config opener = some txid
        /\ Properties.UpToDateWithQuorum config txid := by
  obtain ⟨trace, gossipedState, openedState, opener, openerState,
    gossiped, full, opened, present, kind⟩ := Properties.full_gossip_preserves_commit_witness config multiple
  obtain ⟨txid, recovered, upToDate⟩ :=
    Properties.full_gossip_preserves_commit config trace gossipedState openedState opener openerState
      ⟨gossiped, full, opened, present, by simp [kind]⟩
  exact ⟨opener, txid, recovered, upToDate⟩

example (config : Properties.ValidConfig)
    : exists localStep : Properties.LocalStep,
        localStep.after = localStep.before
        /\ .rejected "gossip-frozen" ∈ localStep.effects.notifications := by
  obtain ⟨localStep, source, txid, valid, action, chosen⟩ :=
    (Properties.gossip_freezes_after_choice config config.property).witness
  exact ⟨localStep,
    (Properties.gossip_freezes_after_choice config config.property).safety localStep source txid
      ⟨valid, action, chosen⟩⟩

example (config : Properties.ValidConfig)
    : exists localStep : Properties.LocalStep,
        localStep.after = localStep.before
        /\ .rejected "quote-or-certificate" ∈ localStep.effects.notifications := by
  obtain ⟨localStep, source, txid, valid, action⟩ :=
    (Properties.rejected_gossip_stutters config config.property).witness
  exact ⟨localStep,
    (Properties.rejected_gossip_stutters config config.property).safety localStep source txid
      ⟨valid, action⟩⟩

example (config : Properties.ValidConfig)
    : exists localStep : Properties.LocalStep,
        localStep.after.phase = .opening
        /\ localStep.after.openKind = some .quorum
        /\ .opening .quorum ∈ localStep.effects.notifications := by
  obtain ⟨localStep, valid, action, phase, quorum⟩ :=
    (Properties.quorum_advance_opens config config.property).witness
  exact ⟨localStep,
    (Properties.quorum_advance_opens config config.property).safety localStep
      ⟨valid, action, phase, quorum⟩⟩

example (config : Properties.ValidConfig)
    : exists localStep : Properties.LocalStep,
        localStep.after = { localStep.before with phase := .open }
        /\ .completed ∈ localStep.effects.notifications := by
  obtain ⟨localStep, valid, action, phase, timeoutState⟩ :=
    (Properties.aligned_opening_timeout_completes config config.property).witness
  exact ⟨localStep,
    (Properties.aligned_opening_timeout_completes config config.property).safety localStep
      ⟨valid, action, phase, timeoutState⟩⟩

end DisasterRecovery.Tests.Witnesses
