module

public import CCFRaft.Proofs.Leadership.AnchorBlocks
public import CCFRaft.Proofs.Leadership.Settles

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# An anchored term stays quiet in a window

For an anchored start, the term stays quiet among participants without the
pre-vote clause and the anchor keeps knowing the primary, at every recorded state
of a good period in which no anchor node retires, provided no anchor node other
than the primary times out in the term at least `fresh` after the start while
the invariant has held so far (`AnchorEngine`). The window lemmas downstream
need only this.
-/

open CCF.Execution (Trace)

namespace CCFRaft.Proofs.Leadership

open CCF CCF.MultiNodeTransitionSystem
open Model.Node
open CCFRaft.Liveness
open CCFRaft.Proofs.Safety
open CCFRaft.Proofs.Replication
open CCFRaft.Proofs.StablePrimary
open CCFRaft.Proofs.Liveness (Admissible)
open HasProtocol (proto)
open HasTime (time)
open HasLive (live)

variable [Config.InitialConfiguration]

/-- The anchored invariant at one state: the term is quiet among participants
without the pre-vote clause, the anchor holds, and no anchor node has retired. -/
structure AnchorBaseInv (participants anchor : Finset NodeID) (leader : NodeID)
    (term : Nat) (state : Model.State)
    : Prop where
  quiet : QuietTerm participants leader term state
  anchored : AnchorBase participants anchor leader term state
  retained
    : forall node local_,
        (node, local_) ∈ state.nodes
        -> node ∈ anchor
        -> Not (local_.isRetiredCommitted node)

/-- The anchored primary tracks every other anchor node at a recorded state. -/
theorem AnchorBaseInv.tracked {participants anchor : Finset NodeID} {leader : NodeID}
    {term : Nat} {point : Model.State}
    (inv : AnchorBaseInv participants anchor leader term point) {node : NodeID}
    (nodeIn : node ∈ anchor) (different : Not (node = leader)) {state : NodeState}
    (leaderFound : nodeState point leader = some state)
    : node ∈ eligiblePeers state leader := by
  have member := inv.anchored.members state (now_of_found leaderFound (rest := []))
    node nodeIn different
  unfold NodeState.activeConfigurations at member
  rw [latest_active] at member
  exact eligible_of_latest member different

/-- An internal event of a selected action is a local step of its actor. -/
theorem anchor_local_of_internal {event : Liveness.Event} {action : Model.Action}
    {actor : NodeID} {localEvent : Model.Node.Event} {input : Input}
    (selected : event.action = some action) (acts : Acts action actor localEvent)
    (internal : localEvent = .internal input)
    : event = .local actor input := by
  cases action with
  | «local» node input' =>
      obtain ⟨actorEq, eventEq⟩ := acts
      rw [eventEq] at internal
      cases internal
      rw [actorEq]
      cases event <;> simp_all [Liveness.Event.action]
  | deliver envelope =>
      obtain ⟨_, eventEq⟩ := acts
      rw [eventEq] at internal
      cases internal

section Recorded

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]

/-- In a good period the anchored primary has a live quorum within the anchor. -/
theorem AnchorBaseInv.liveQuorum {start : Nat} {duration : Real}
    {participants anchor : Finset NodeID} {leader : NodeID} {term index : Nat} {point : W}
    {trace : Trace W Liveness.Event} (good : GoodBase trace start duration participants)
    (within : Within trace start duration index)
    (found : trace.stateAt index = some point)
    (inv : AnchorBaseInv participants anchor leader term (proto point))
    {state : NodeState} (leaderFound : nodeState (proto point) leader = some state)
    : hasQuorum state.activeConfigurations (Inter.inter (live point) anchor) := by
  refine hasQuorum_mono (inv.anchored.quorum state (now_of_found leaderFound (rest := [])))
    fun node nodeIn => Finset.mem_inter.mpr ⟨?_, nodeIn⟩
  exact good.participantsLive index point node within found (inv.anchored.subset nodeIn)

/-- An anchored window invariant from `start`: the anchor holds the primary among
the participants, and below any bound `AnchorBaseInv` and `NoProposals` hold at
every recorded state of the window, provided no anchor node other than the primary
times out in the term at least `fresh` after the start while they have held so
far. The window lemmas downstream need only this, so starts that differ in how
they keep the anchor share them. -/
structure AnchorEngine (trace : Trace W Liveness.Event) (start : Nat) (duration : Real)
    (leader : NodeID) (term : Nat) (participants anchor : Finset NodeID) (fresh : Real)
    : Prop where
  subset : anchor ⊆ participants
  leaderIn : leader ∈ anchor
  core
    : forall bound,
        (forall index step node state first,
          start <= index
          -> index < bound
          -> Within trace start duration index
          -> trace.stepAt index = some step
          -> step.action = .local node (.timeout .election)
          -> nodeState (proto step.before) node = some state
          -> node ∈ anchor
          -> Not (node = leader)
          -> state.currentTerm = term
          -> trace.stateAt start = some first
          -> time first + fresh <= time step.before
          -> (forall earlier point,
                start <= earlier
                -> earlier <= index
                -> trace.stateAt earlier = some point
                -> AnchorBaseInv participants anchor leader term (proto point)
                    /\ NoProposals participants term point)
          -> False)
        -> forall index point,
            index <= bound
            -> Within trace start duration index
            -> trace.stateAt index = some point
            -> AnchorBaseInv participants anchor leader term (proto point)
                /\ NoProposals participants term point

variable {nodes : List NodeID}
  {trace : Trace W Liveness.Event}
  (admissible : Admissible Config.INITIAL_CONFIGURATION nodes trace)

include admissible

/-- An anchor node is no pre-vote candidate, so the term is quiet among the
anchor with the pre-vote clause. -/
theorem AnchorBaseInv.quietAmong {participants anchor : Finset NodeID} {leader : NodeID}
    {term index : Nat} {point : W} (found : trace.stateAt index = some point)
    (inv : AnchorBaseInv participants anchor leader term (proto point))
    : QuietAmong anchor leader term (proto point) := by
  obtain ⟨_, exec⟩ := history_at admissible found
  refine ⟨
    fun node local_ member nodeIn =>
      inv.quiet.terms node local_ member (inv.anchored.subset nodeIn),
    fun node local_ member nodeIn role => ?_,
    fun envelope member sourceIn targetIn =>
      inv.quiet.messages envelope member (inv.anchored.subset sourceIn)
        (inv.anchored.subset targetIn),
    inv.quiet.leader
  ⟩
  exfalso
  obtain ⟨settled, settledNow, _, _, followerOrPrimary⟩ := inv.anchored.settled node nodeIn
  have same := (found_of_now exec settledNow).symm.trans (found_of_now exec member)
  rw [Option.some.injEq] at same
  subst same
  rcases followerOrPrimary with r | r <;> rw [r] at role <;> cases role

/-- The anchored primary leads `term` at a recorded state. -/
theorem AnchorBaseInv.leads {participants anchor : Finset NodeID} {leader : NodeID}
    {term index : Nat} {point : W} (found : trace.stateAt index = some point)
    (inv : AnchorBaseInv participants anchor leader term (proto point))
    : exists state,
        nodeState (proto point) leader = some state
        /\ state.role = .primary
        /\ state.currentTerm = term := by
  obtain ⟨_, exec⟩ := history_at admissible found
  obtain ⟨local_, now, primary, termEq⟩ := inv.quiet.leader
  exact ⟨local_, found_of_now exec now, primary, termEq⟩

end Recorded

end CCFRaft.Proofs.Leadership
