module

public import CCFRaft.Proofs.Replication.Step
public import CCFRaft.Properties.Liveness.Assumptions.Window

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# No outstanding proposals

`NoProposals` is over the packet ledger. A step keeps it unless it emits a
proposal for the term between participants, and a delivery between participants
is never such a proposal, since a delivered packet was outstanding.
-/

open CCF.Execution (Trace)

namespace CCFRaft.Proofs.Leadership

open CCF CCF.MultiNodeTransitionSystem
open Model.Node
open CCFRaft.Liveness
open CCFRaft.Proofs.StablePrimary (Acts)
open HasProtocol (proto)
open HasNetwork (pending)

variable [Config.InitialConfiguration]
  {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]
  {trace : Trace W Liveness.Event} {nodes : List NodeID}
  (admissible
    : CCFRaft.Proofs.Liveness.Admissible Config.INITIAL_CONFIGURATION nodes trace)
  {participants : Finset NodeID} {term : Nat}

/-- No proposal is outstanding between fewer participants. -/
theorem NoProposals.mono {point : W} {smaller : Finset NodeID}
    (quiet : NoProposals participants term point) (subset : smaller ⊆ participants)
    : NoProposals smaller term point :=
  fun packet member sourceIn targetIn =>
    quiet packet member (subset sourceIn) (subset targetIn)

include admissible

/-- A step keeps no proposal outstanding if it emits none between participants. -/
theorem NoProposals.after {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step)
    (quiet : NoProposals participants term step.before)
    (fresh
      : forall action emitted envelope,
          step.action.action = some action
          -> outgoing (proto step.before) action = some emitted
          -> envelope ∈ emitted
          -> envelope.source ∈ participants
          -> envelope.target ∈ participants
          -> Not (envelope.payload = .proposeRequestVoteRequest term))
    : NoProposals participants term step.after := by
  intro packet member sourceIn targetIn
  by_cases old : packet ∈ pending step.before
  · exact quiet packet old sourceIn targetIn
  · obtain ⟨step', action, emitted, stepped', selected, out, emits, _⟩ :=
      admissible.sentAt_emitted ⟨step, stepped, member, old⟩
    rw [stepped, Option.some.injEq] at stepped'
    subst stepped'
    exact fresh action emitted packet.envelope selected out emits sourceIn targetIn

/-- A protocol step of a context keeps no proposal outstanding if it sends none
between participants. -/
theorem NoProposals.after_sent {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step) {action : Model.Action}
    (selected : step.action.action = some action) {sent : List Model.Envelope}
    (out : outgoing (proto step.before) action = some sent)
    (quiet : NoProposals participants term step.before)
    (fresh
      : forall envelope,
          envelope ∈ sent
          -> envelope.source ∈ participants
          -> envelope.target ∈ participants
          -> Not (envelope.payload = .proposeRequestVoteRequest term))
    : NoProposals participants term step.after :=
  NoProposals.after admissible stepped quiet
    fun action' emitted envelope selected' out' emits => by
      rw [selected, Option.some.injEq] at selected'
      subst selected'
      rw [out, Option.some.injEq] at out'
      subst out'
      exact fresh envelope emits

/-- A stuttering step keeps no proposal outstanding. -/
theorem NoProposals.stutter {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step) (selected : step.action.action = none)
    (quiet : NoProposals participants term step.before)
    : NoProposals participants term step.after :=
  NoProposals.after admissible stepped quiet
    fun _ _ _ selected' => by
      rw [selected] at selected'
      cases selected'

/-- A participant never receives a proposal for the term from a participant while
none is outstanding. -/
theorem NoProposals.not_received {index : Nat}
    {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step) {action : Model.Action}
    (selected : step.action.action = some action) {actor : NodeID}
    {event : Model.Node.Event} (acts : Acts action actor event)
    (quiet : NoProposals participants term step.before) (actorIn : actor ∈ participants)
    {source : NodeID}
    (eventEq : event = .receive source (.proposeRequestVoteRequest term))
    (sourceIn : source ∈ participants)
    : False := by
  cases action with
  | «local» node input =>
      obtain ⟨_, eventEq'⟩ := acts
      cases eventEq'.symm.trans eventEq
  | deliver envelope =>
      obtain ⟨actorEq, eventEq'⟩ := acts
      obtain ⟨sourceEq, payload⟩ := Model.Node.Event.receive.inj (eventEq'.symm.trans eventEq)
      cases action : step.action with
      | deliver packet =>
          rw [action] at selected
          simp only [Event.action, Option.some.injEq] at selected
          cases selected
          have member := admissible.consumed_pending stepped (by rw [action]; rfl)
          exact quiet packet member (sourceEq ▸ sourceIn) (actorEq ▸ actorIn) payload
      | «local» _ _ | drop _ | crash _ | idle =>
          rw [action] at selected
          simp [Event.action] at selected

end CCFRaft.Proofs.Leadership
