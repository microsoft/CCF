module

public import CCFRaft.Proofs.Liveness
public import CCFRaft.Proofs.Safety.Commit

import all Init.Control.State

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# A stable primary's log

Log facts for the commit argument: a stable primary keeps every entry it ever had
while it leads, a signing append adds a current-term signature, and with no
signature due its whole log is covered by its latest signature.
They reuse the safety invariant, so a primary keeps its log for as long as it
stays primary in the same term.
-/

open CCF.Execution (Trace)

namespace CCFRaft.Proofs.CommitLiveness

open CCFRaft.Proofs.Config
open CCF CCF.MultiNodeTransitionSystem
open Model.Node
open CCFRaft.Liveness
open CCFRaft.Proofs.Safety
open CCFRaft.Proofs.Liveness (Admissible)
open CCFRaft.Proofs.Direct (Keeps)
open HasProtocol (proto)

/-! ## Protocol steps -/

section Steps

variable [Config.InitialConfiguration]

/-- A node that is primary in the same term at both ends keeps its earlier log. -/
theorem primary_log_prefix {nodes : List NodeID} {history history' : List Model.State}
    {before after : Model.State}
    (exec : Exec nodes (before :: history)) (exec' : Exec nodes (after :: history'))
    (suffix : (before :: history) <:+ (after :: history'))
    {leader : NodeID} {old new : NodeState}
    (oldFound : nodeState before leader = some old)
    (newFound : nodeState after leader = some new)
    (oldPrimary : old.role = .primary) (newPrimary : new.role = .primary)
    (sameTerm : old.currentTerm = new.currentTerm)
    : old.log <+: new.log := by
  have inv := good_of_exec exec _ (List.suffix_refl _) (List.cons_ne_nil _ _)
  have inv' := good_of_exec exec' _ (List.suffix_refl _) (List.cons_ne_nil _ _)
  have oldNow : Now (before :: history) leader old := Concrete.mem_of_nodeState oldFound
  have newNow : Now (after :: history') leader new := Concrete.mem_of_nodeState newFound
  have canon : Canon (before :: history) old.currentTerm old.log :=
    ⟨_, List.suffix_refl _, leader, old,
      ⟨oldNow, rfl, by rw [oldPrimary]; decide,
        inv.leader_led leader old oldNow oldPrimary⟩, rfl⟩
  have led := inv'.leader_led leader new newNow newPrimary
  exact (inv'.canon_mono leader new newNow (by rw [newPrimary]; decide) led).1 _
    (sameTerm ▸ canon.mono suffix)

/-- The actor of a local step is found afterwards with its new state. -/
theorem local_step_found {nodes : List NodeID} {before after : Model.State}
    {node : NodeID} {input : Input}
    (reachable
      : (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes).Reachable before)
    (stepped
      : (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes).step before
          (.local node input)
        = some after)
    : exists state next outputs,
        nodeState before node = some state
        /\ (act (Capabilities.record node) node state input).run {} = some (next, outputs)
        /\ nodeState after node = some next := by
  have distinct := Direct.keys_nodup (TransitionSystem.Reachable.step reachable stepped)
  obtain ⟨state, next, outputs, found, ran, rfl⟩ := Concrete.step_local stepped
  refine ⟨state, next, outputs, found, ran, Direct.nodeState_of_mem distinct ?_⟩
  exact List.mem_map.mpr ⟨(node, state), Concrete.mem_of_nodeState found, by simp⟩

end Steps

/-! ## Appending entries -/

section Append

variable (caps : Caps) (self : NodeID)

theorem appendEntry_log (state : NodeState) (content : EntryContent)
    : Keeps
        (fun after =>
          after.log = state.log ++ [{ term := state.currentTerm, content }]
          /\ after.currentTerm = state.currentTerm)
        (appendEntry caps self state content) := by
  unfold appendEntry
  simp only [pure_bind]
  repeat'
    first
    | exact Keeps.pure' ⟨rfl, rfl⟩
    | refine Keeps.ite' (fun _ => ?_) fun _ => ?_
    | refine Keeps.seq' fun _ => ?_
    | split

end Append

/-- Entries appended at the current term, in order. -/
abbrev appended (term : Nat) (contents : List EntryContent) : List Entry :=
  contents.map fun content => { term, content }

theorem foldAppend_log (self : NodeID)
    : forall (contents : List EntryContent) (state : NodeState),
        Keeps
          (fun after =>
            after.log = state.log ++ appended state.currentTerm contents
            /\ after.currentTerm = state.currentTerm)
          (contents.foldlM (appendEntry (Capabilities.record self) self) state)
  | [], state => by
      simp only [List.foldlM_nil]
      exact Keeps.pure' ⟨by simp, rfl⟩
  | content :: rest, state => by
      simp only [List.foldlM_cons]
      exact Keeps.bind' (appendEntry_log _ self state content) fun middle ⟨log, term⟩ =>
        (foldAppend_log self rest middle).mono fun _ ⟨log', term'⟩ =>
          ⟨by rw [log', log, term]; simp, term'.trans term⟩

/-- Commit advancement never touches the log or the term. -/
theorem advanceCommit_log (self : NodeID) (state : NodeState)
    : Keeps (fun after => after.log = state.log /\ after.currentTerm = state.currentTerm)
        (advanceCommit (Capabilities.record self) state self) := by
  intro outputs result after ran
  obtain ⟨_, _, advance, _⟩ := advanceCommit_sends self state outputs result after ran
  rcases advance with ⟨rfl, _⟩ | ⟨log, term, _⟩
  · exact ⟨rfl, rfl⟩
  · exact ⟨log, term⟩

theorem append_log (self : NodeID) (state : NodeState) (contents : List EntryContent)
    : Keeps
        (fun after =>
          after.log = state.log ++ appended state.currentTerm contents
          /\ after.currentTerm = state.currentTerm)
        (act (Capabilities.record self) self state (.append contents)) := by
  unfold act appendBatch
  refine Keeps.seq' fun _ => ?_
  exact Keeps.bind' (foldAppend_log self contents state) fun middle ⟨log, term⟩ =>
    (advanceCommit_log self middle).mono fun _ ⟨log', term'⟩ =>
      ⟨log'.trans log, term'.trans term⟩

theorem entryAt_appended (log : List Entry) (term : Nat) (contents : List EntryContent)
    (position : Nat) (within : position < contents.length)
    : entryAt? (log ++ appended term contents) (log.length + position + 1)
      = some { term, content := contents[position] } := by
  simp [entryAt?, within]

/-! ## Reaching a covering signature -/

section Recorded

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]
  {trace : Trace W Liveness.Event}

/-- With no signature due, a stable primary's whole log is covered by its latest
signature, which is from the current term. -/
theorem signed_of_not_due {start : Nat} {leader : NodeID} {term : Nat}
    (stable : StableLeader trace start leader term) {index : Nat} {point : W}
    (le : start <= index) (found : trace.stateAt index = some point) {state : NodeState}
    (nodeFound : nodeState (proto point) leader = some state)
    (notDue : Not (SignatureDue point leader))
    (nonempty : Not (state.log = []))
    : isSignatureAt state.log state.log.length = true
      /\ termAt state.log state.log.length = term := by
  obtain ⟨live, state', nodeFound', primary, currentTerm, active⟩ := stable.leads le found
  rw [nodeFound, Option.some.injEq] at nodeFound'
  subst nodeFound'
  have covered : maxCommittableIndex state.log = state.log.length
      /\ maxCommittableTerm state.log = term := by
    by_contra uncovered
    have bounded := Ledger.maxCommittableIndexBounded state.log
    exact notDue ⟨live, state, nodeFound, primary, active, by grind⟩
  have positive : 0 < maxCommittableIndex state.log := by
    rw [covered.1]; exact List.length_pos_iff.mpr nonempty
  have signature := Ledger.maxCommittableIndexPositiveIsSignature positive
  rw [covered.1] at signature
  refine ⟨signature, ?_⟩
  have := covered.2
  unfold maxCommittableTerm at this
  rwa [covered.1] at this

variable [Config.InitialConfiguration] {nodes : List NodeID}
  (admissible : Admissible Config.INITIAL_CONFIGURATION nodes trace)

include admissible

/-- Environment-only events leave the history unchanged; protocol events extend it. -/
theorem history_extends {index later : Nat} (le : index <= later) {first last : W}
    (firstFound : trace.stateAt index = some first)
    (lastFound : trace.stateAt later = some last) {history : List Model.State}
    (exec : Exec nodes (proto first :: history))
    : exists history',
        Exec nodes (proto last :: history')
        /\ (proto first :: history) <:+ (proto last :: history') :=
  trace.induction
    (start := index)
    (motive :=
      fun _ point =>
        exists history',
          Exec nodes (proto point :: history')
          /\ (proto first :: history) <:+ (proto point :: history'))
    (fun point found => by
      rw [firstFound, Option.some.injEq] at found
      subst found
      exact ⟨history, exec, List.suffix_refl _⟩)
    (fun _ step _ stepped ⟨history', exec', suffix⟩ => by
      cases selected : step.action.action with
      | none =>
          rw [admissible.stutter stepped selected]
          exact ⟨history', exec', suffix⟩
      | some action =>
          exact ⟨_, .step exec' (admissible.step stepped selected),
            suffix.trans (List.suffix_cons _ _)⟩)
    later last le lastFound

/-- A stable primary keeps every entry it ever had while it leads. -/
theorem stable_log_prefix {start : Nat} {leader : NodeID} {term : Nat}
    (stable : StableLeader trace start leader term) {index later : Nat}
    (afterStart : start <= index) (le : index <= later) {old new : NodeState}
    (oldFound : nodeAt trace index leader = some old)
    (newFound : nodeAt trace later leader = some new)
    : old.log <+: new.log := by
  obtain ⟨first, firstFound, oldFound'⟩ := nodeAt_eq_some.mp oldFound
  obtain ⟨last, lastFound, newFound'⟩ := nodeAt_eq_some.mp newFound
  obtain ⟨history, exec⟩ := exec_of_reachable (admissible.reachable firstFound)
  obtain ⟨history', exec', suffix⟩ := history_extends admissible le firstFound lastFound exec
  have laterStart := Nat.le_trans afterStart le
  exact primary_log_prefix exec exec' suffix oldFound' newFound'
    (stable.primary afterStart oldFound) (stable.primary laterStart newFound)
    ((stable.current afterStart oldFound).trans (stable.current laterStart newFound).symm)

/-- After a signing append the primary's log has a current-term signature past its
previous end. -/
theorem signs_step {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step) {leader : NodeID}
    (signs : Signs step leader)
    : exists before after signature,
        nodeAt trace index leader = some before
        /\ nodeAt trace (index + 1) leader = some after
        /\ before.log.length < signature
        /\ isSignatureAt after.log signature = true
        /\ termAt after.log signature = before.currentTerm := by
  obtain ⟨entries, action, member⟩ := signs
  obtain ⟨before, after, _, found, ran, found'⟩ :=
    local_step_found (admissible.reachable_before stepped)
      (admissible.step stepped (by rw [action]; rfl))
  obtain ⟨log, _⟩ := append_log leader before entries _ _ _ ran
  obtain ⟨position, within, signature⟩ := List.mem_iff_getElem.mp member
  have entry := entryAt_appended before.log before.currentTerm entries position within
  refine ⟨
    before,
    after,
    before.log.length + position + 1,
    by rw [nodeAt_of_stateAt (Trace.stateAt_of_stepAt stepped), found],
    by rw [nodeAt_of_stateAt (Trace.stateAt_succ_of_stepAt stepped), found'],
    by omega,
    ?_,
    ?_
  ⟩
  · simp [isSignatureAt, log, entry, signature, EntryContent.isSignature]
  · simp [termAt, log, entry]

/-! ## Reaching the request -/

/-! ## The reduction -/

end Recorded

end CCFRaft.Proofs.CommitLiveness
