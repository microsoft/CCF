module

public import Consensus.Model

import CCF.Lemma
import CCF.Order
import all Init.Control.State

public import CCF.Execution

namespace Consensus.Proofs.Config

open CCF (Finset)
open Model.Node

/-- The initial membership passed to the model, possibly empty. -/
private class InitialConfiguration where
  configuration : Finset NodeID

end Consensus.Proofs.Config

namespace Consensus.Proofs.Config

open CCF (Finset)
open Model.Node
section Initial
variable [config : InitialConfiguration]

private abbrev INITIAL_CONFIGURATION : Finset NodeID := config.configuration

end Initial
end Consensus.Proofs.Config

namespace Consensus.Proofs.Concrete

set_option linter.unusedSectionVars false
open Consensus.Proofs.Config
open CCF CCF.MultiNodeTransitionSystem
open Model.Node

/-- Replace the state of `node` in a node table. -/
private def replaceNode (nodes : List (NodeID × NodeState)) (node : NodeID)
    (value : NodeState)
    : List (NodeID × NodeState) :=
  nodes.map fun entry => if entry.1 == node then (node, value) else entry

end Consensus.Proofs.Concrete

namespace Consensus.Proofs.Direct

set_option linter.unusedSectionVars false
open Consensus.Proofs.Config
open CCF CCF.MultiNodeTransitionSystem Concrete
open Model.Node
open Model (initialNodeState)
variable [Config.InitialConfiguration]

/-- A node-local predicate that holds initially and survives every local step. -/
private structure NodeInvariant (P : NodeID -> NodeState -> Prop) : Prop where
  initial : forall node, P node (initialNodeState Config.INITIAL_CONFIGURATION node)
  step
    : forall node state event after outputs,
        P node state
        -> (Model.Node.step (Capabilities.record node) node state event).run {}
            = some (after, outputs)
        -> P node after

end Consensus.Proofs.Direct

namespace Consensus.Proofs.Direct

set_option linter.unusedSectionVars false
open CCF
variable {Node Message Notification : Type}

/-- Every successful run of `m` returns a value satisfying `P`. -/
private def Keeps {α : Type} (P : α -> Prop) (m : Effect Node Message Notification α)
    : Prop :=
  forall outputs result after, m.run outputs = some (result, after) -> P result

end Consensus.Proofs.Direct

namespace Consensus.Proofs.Ledger
end Consensus.Proofs.Ledger

namespace Consensus.Proofs.Direct.Keeps
end Consensus.Proofs.Direct.Keeps

namespace Consensus.Proofs.Direct

set_option linter.unusedSectionVars false
open Consensus.Proofs.Config
open CCF
open Model.Node

/-- The commit index lies within the log and, when positive, is a signature. -/
private def CommitFrontier (state : NodeState) : Prop :=
  state.commitIndex <= state.log.length
  /\ (0 < state.commitIndex -> isSignatureAt state.log state.commitIndex = true)

end Consensus.Proofs.Direct

namespace Consensus.Proofs.Direct

set_option linter.unusedSectionVars false
open Consensus.Proofs.Config
open CCF CCF.MultiNodeTransitionSystem Concrete
open Model.Node

/-- `after` commits no less than `before` and its log extends the committed log
of `before`. No relation between `before`'s commit index and log is assumed. -/
private def Extends (before after : NodeState) : Prop :=
  before.commitIndex <= after.commitIndex /\ before.committedLog <+: after.log

end Consensus.Proofs.Direct

namespace Consensus.Proofs.Concrete

set_option linter.unusedSectionVars false
open Consensus.Proofs.Config
open CCF CCF.MultiNodeTransitionSystem
open Model.Node
section Steps
variable [Config.InitialConfiguration]

private theorem step_local
    {nodes : List NodeID} {before after : Model.State}
    {node : NodeID} {input : Model.Node.Input}
    (stepped
      : (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes).step before
          (.local node input)
        = some after)
    : exists state next outputs,
        nodeState before node = some state
        /\ (Model.Node.act (Capabilities.record node) node state input).run {}
            = some (next, outputs)
        /\ after
            = {
              before with
                nodes := replaceNode before.nodes node next
                network := before.network ++ outputs.outgoing
            } := by
  simp only [Model.transitionSystem, lift, next, Model.protocol] at stepped
  simp [Model.Node.step, Option.bind_eq_some_iff] at stepped
  obtain ⟨state, found, next, outputs, ran, rfl⟩ := stepped
  refine ⟨state, next, outputs, found, ?_, by simp [replaceNode]⟩
  exact ran

private theorem step_deliver
    {nodes : List NodeID} {before after : Model.State}
    {envelope : Model.Envelope}
    (stepped
      : (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes).step before
          (.deliver envelope)
        = some after)
    : envelope ∈ before.network
      /\ exists state next outputs,
          nodeState before envelope.target = some state
          /\ (Model.Node.receive (Capabilities.record envelope.target)
                envelope.target envelope.source state
                envelope.payload).run
                {}
              = some (next, outputs)
          /\ after
              = {
                before with
                  nodes := replaceNode before.nodes envelope.target next
                  network := removeOne envelope before.network ++ outputs.outgoing
              } := by
  simp only [Model.transitionSystem, lift, next, Model.protocol] at stepped
  simp [Model.Node.step, Option.bind_eq_some_iff, guard] at stepped
  obtain ⟨queued, state, found, next, outputs, ran, rfl⟩ := stepped
  exact ⟨queued, state, next, outputs, found, ran, by simp [replaceNode]⟩

end Steps
end Consensus.Proofs.Concrete

namespace Consensus.Proofs.Concrete

set_option linter.unusedSectionVars false
open Consensus.Proofs.Config
open CCF CCF.MultiNodeTransitionSystem
open Model.Node

private theorem mem_replaceNode {nodes : List (NodeID × NodeState)} {node member : NodeID}
    {value state : NodeState}
    (found : (member, state) ∈ replaceNode nodes node value)
    : (member = node /\ state = value)
      \/ (Not (member = node) /\ (member, state) ∈ nodes) := by
  simp only [replaceNode, List.mem_map] at found
  obtain ⟨⟨key, old⟩, listed, same⟩ := found
  by_cases here : key = node
  · simp only [here, beq_self_eq_true, ite_true, Prod.mk.injEq] at same
    exact Or.inl ⟨same.1.symm, same.2.symm⟩
  · have different : (key == node) = false := by simpa using here
    simp only [different, Bool.false_eq_true, ite_false, Prod.mk.injEq] at same
    obtain ⟨rfl, rfl⟩ := same
    exact Or.inr ⟨here, listed⟩

private theorem mem_of_nodeState {concrete : Model.State} {node : NodeID}
    {state : NodeState} (found : nodeState concrete node = some state)
    : (node, state) ∈ concrete.nodes := by
  simp only [nodeState, Option.map_eq_some_iff] at found
  obtain ⟨⟨key, value⟩, located, rfl⟩ := found
  have same : key = node := by simpa using List.find?_some located
  subst same
  exact List.mem_of_find?_eq_some located

private theorem observeTerm_log (state : NodeState) (message : Model.Node.Message)
    : (Model.Node.observeTerm state message).log = state.log := by
  unfold Model.Node.observeTerm Model.Node.updateTerm
  split <;> (try split) <;> (try split) <;> rfl

private theorem observeTerm_commitIndex (state : NodeState) (message : Model.Node.Message)
    : (Model.Node.observeTerm state message).commitIndex = state.commitIndex := by
  unfold Model.Node.observeTerm Model.Node.updateTerm
  split <;> (try split) <;> (try split) <;> rfl

end Consensus.Proofs.Concrete

namespace Consensus.Proofs.Ledger

set_option linter.unusedSectionVars false
open Consensus.Proofs.Config
open Consensus.Model.Node

@[simp]
private lemma EntryContent.isSignature_eq_true {content : EntryContent}
    : content.isSignature = true <-> content = .signature := by
  cases content <;> simp [EntryContent.isSignature]

/-- A successful one-based lookup proves the index lies within the log. -/
private lemma entryAtSomeIndexBound
    {log : List Entry}
    {index : Nat}
    {entry : Entry}
    (found : entryAt? log index = some entry)
    : index <= log.length := by
  unfold entryAt? at found
  split at found
  · simp_all
  · rename_i indexNotZero
    rw [List.getElem?_eq_some_iff] at found
    rcases found with ⟨within, _⟩
    rw [← Nat.sub_add_cancel (Nat.pos_of_ne_zero indexNotZero)]
    exact within

/-- A successful lookup is unchanged when the log is extended at the end. -/
private lemma entryAt_of_prefix
    {left right : List Entry}
    (isPrefix : left <+: right)
    {index : Nat}
    {entry : Entry}
    (found : entryAt? left index = some entry)
    : entryAt? right index = some entry := by
  rcases isPrefix with ⟨suffix, rightEq⟩
  rw [← rightEq]
  unfold entryAt? at found ⊢
  by_cases zero : index = 0
  · simp [zero] at found
  · simp only [zero, ↓reduceIte] at found ⊢
    have within : index - 1 < left.length := by
      rw [List.getElem?_eq_some_iff] at found
      exact found.1
    rw [List.getElem?_append_left within]
    exact found

/-- A positive signature test identifies a concrete signature entry. -/
private lemma isSignatureAtTrue
    {log : List Entry}
    {index : Nat}
    (signature : isSignatureAt log index = true)
    : Exists
        fun entry =>
          entryAt? log index = some entry /\ entry.content = .signature := by
  cases found : entryAt? log index with
  | none =>
      simp [isSignatureAt, found] at signature
  | some entry =>
      refine ⟨entry, rfl, ?_⟩
      simpa [isSignatureAt, found] using signature

/-- The latest signature index lies within the log. -/
private lemma maxCommittableIndexBounded (log : List Entry)
    : maxCommittableIndex log <= log.length := by
  unfold maxCommittableIndex
  let candidates := List.range (log.length + 1)
  let choose :=
    fun best index =>
      if isSignatureAt log index then max best index else best
  have allBounded :
      forall index,
        index ∈ candidates ->
          index <= log.length := by
    intro index member
    simp [candidates] at member
    exact Nat.le_of_lt_succ member
  have foldBounded :
      forall (values : List Nat) (best : Nat),
        (forall index, index ∈ values -> index <= log.length) ->
        best <= log.length ->
        values.foldl choose best <= log.length := by
    intro values
    induction values with
    | nil =>
        intro best _ bestBound
        exact bestBound
    | cons head tail inductionHypothesis =>
        intro best valuesBound bestBound
        apply inductionHypothesis
        · intro index member
          exact valuesBound index (by simp [member])
        · have headBound := valuesBound head (by simp)
          simp only [choose]
          split
          · exact Nat.max_le.mpr ⟨bestBound, headBound⟩
          · exact bestBound
  change candidates.foldl choose 0 <= log.length
  exact foldBounded candidates 0 allBounded (Nat.zero_le _)

/-- A positive latest committable index points to a signature. -/
private lemma maxCommittableIndexPositiveIsSignature
    {log : List Entry}
    (positive : 0 < maxCommittableIndex log)
    : isSignatureAt log (maxCommittableIndex log) = true := by
  unfold maxCommittableIndex at positive ⊢
  let valid := fun index => isSignatureAt log index = true
  let choose :=
    fun best index =>
      if valid index then max best index else best
  have foldValid :
      forall (values : List Nat) (best : Nat),
        (best = 0 \/ valid best) ->
        let result := values.foldl choose best
        result = 0 \/ valid result := by
    intro values
    induction values with
    | nil =>
        intro best bestValid
        exact bestValid
    | cons head tail inductionHypothesis =>
        intro best bestValid
        apply inductionHypothesis
        simp only [choose]
        by_cases headValid : valid head
        · simp [headValid]
          rcases bestValid with bestZero | bestIsValid
          · subst best
            exact Or.inr headValid
          · by_cases bestLeHead : best <= head
            · right
              simpa [Nat.max_eq_right bestLeHead] using headValid
            · right
              have headLeBest : head <= best := Nat.le_of_lt (Nat.lt_of_not_le bestLeHead)
              simpa [Nat.max_eq_left headLeBest] using bestIsValid
        · simp [headValid, bestValid]
  have resultValid :=
    foldValid (List.range (log.length + 1)) 0 (Or.inl rfl)
  rcases resultValid with resultZero | resultValid
  · rw [resultZero] at positive
    exact absurd positive (Nat.lt_irrefl 0)
  · exact resultValid

/-- Every signature index is no later than the latest signature index. -/
private lemma signatureIndex_le_maxCommittableIndex
    {log : List Entry}
    {index : Nat}
    (signature : isSignatureAt log index = true)
    : index <= maxCommittableIndex log := by
  have indexBound : index <= log.length := by
    rcases isSignatureAtTrue signature with ⟨entry, found, _⟩
    exact entryAtSomeIndexBound found
  unfold maxCommittableIndex
  let candidates := List.range (log.length + 1)
  let choose :=
    fun best candidate =>
      if isSignatureAt log candidate then
        max best candidate
      else
        best
  have foldAboveStart :
      forall (values : List Nat) (best : Nat),
        best <= values.foldl choose best := by
    intro values
    induction values with
    | nil =>
        intro best
        exact Nat.le.refl
    | cons head tail inductionHypothesis =>
        intro best
        apply Nat.le_trans (m := choose best head)
        · simp only [choose]
          split
          · exact Nat.le_max_left _ _
          · exact Nat.le.refl
        · exact inductionHypothesis (choose best head)
  have foldContains :
      forall (values : List Nat) (best : Nat),
        index ∈ values ->
          index <= values.foldl choose best := by
    intro values
    induction values with
    | nil =>
        simp
    | cons head tail inductionHypothesis =>
        intro best member
        simp only [List.foldl_cons]
        rcases List.mem_cons.mp member with headEq | tailMember
        · subst head
          have selected :
              choose best index = max best index := by
            simp [choose, signature]
          rw [selected]
          exact (Nat.le_max_right best index).trans (foldAboveStart tail (max best index))
        · exact
            inductionHypothesis
              (choose best head) tailMember
  change index <= candidates.foldl choose 0
  exact foldContains candidates 0
    (by
      simp [candidates]
      exact Nat.lt_succ_of_le indexBound)

/-- Extending a log preserves every earlier signature lookup. -/
private lemma isSignatureAt_of_prefix
    {left right : List Entry}
    (isPrefix : left <+: right)
    {index : Nat}
    (signature : isSignatureAt left index = true)
    : isSignatureAt right index = true := by
  rcases isSignatureAtTrue signature with ⟨entry, found, content⟩
  have extended := entryAt_of_prefix isPrefix found
  simp [isSignatureAt, extended, content]

/-- Extending a log cannot move its latest signature backwards. -/
private lemma maxCommittableIndex_le_of_prefix
    {left right : List Entry}
    (isPrefix : left <+: right)
    : maxCommittableIndex left <= maxCommittableIndex right := by
  by_cases zero : maxCommittableIndex left = 0
  · rw [zero]
    exact Nat.zero_le _
  · have positive : 0 < maxCommittableIndex left :=
      Nat.pos_of_ne_zero zero
    exact
      signatureIndex_le_maxCommittableIndex
        (isSignatureAt_of_prefix isPrefix
          (maxCommittableIndexPositiveIsSignature positive))

/-- Taking a log prefix leaves lookups inside that prefix unchanged. -/
private lemma isSignatureAt_take_of_le
    {log : List Entry}
    {index count : Nat}
    (within : index <= count)
    (signature : isSignatureAt log index = true)
    : isSignatureAt (log.take count) index = true := by
  rcases isSignatureAtTrue signature with ⟨entry, found, content⟩
  have taken : entryAt? (log.take count) index = some entry := by
    by_cases zero : index = 0
    · subst index
      simp [entryAt?] at found
    · unfold entryAt? at found ⊢
      simp only [zero, ↓reduceIte] at found ⊢
      rw [List.getElem?_take]
      split
      · exact found
      · rename_i outside
        exact absurd (Nat.lt_of_lt_of_le (Nat.sub_one_lt zero) within) outside
  simp [isSignatureAt, taken, content]

/-- The bounded committable frontier does not exceed the complete log. -/
private lemma maxCommittableIndexUpTo_le_length (log : List Entry) (frontier : Nat)
    : maxCommittableIndexUpTo log frontier <= log.length := by
  unfold maxCommittableIndexUpTo
  have bounded :=
    maxCommittableIndexBounded (log.take frontier)
  simp only [List.length_take] at bounded
  exact Nat.le_trans bounded (Nat.min_le_right _ _)

/-- A positive bounded committable frontier points to a signature in the log. -/
private lemma maxCommittableIndexUpToPositiveIsSignature
    {log : List Entry}
    {frontier : Nat}
    (positive : 0 < maxCommittableIndexUpTo log frontier)
    : isSignatureAt log (maxCommittableIndexUpTo log frontier) = true := by
  unfold maxCommittableIndexUpTo at positive ⊢
  exact
    isSignatureAt_of_prefix
      (List.take_prefix frontier log)
      (maxCommittableIndexPositiveIsSignature positive)

/-- Recording a commit changes the commit index and retirement latch, and may
clear the role and primary knowledge. -/
private lemma NodeState.recordCommit_eq (node : NodeID) (state : NodeState) (index : Nat)
    : exists retiredCommittedIndex role primaryKnown,
        state.recordCommit node index
          = { state with commitIndex := index, retiredCommittedIndex, role, primaryKnown }
        /\ (role = state.role \/ role = .none) := by
  unfold NodeState.recordCommit
  dsimp only
  split
  · exact ⟨_, _, _, rfl, Or.inr rfl⟩
  · exact ⟨_, _, _, rfl, Or.inl rfl⟩

@[simp]
private lemma NodeState.recordCommit_log (node : NodeID) (state : NodeState) (index : Nat)
    : (state.recordCommit node index).log = state.log := by
  obtain ⟨_, _, _, eq, _⟩ := NodeState.recordCommit_eq node state index
  rw [eq]

@[simp]
private lemma NodeState.recordCommit_commitIndex (node : NodeID) (state : NodeState)
    (index : Nat)
    : (state.recordCommit node index).commitIndex = index := by
  obtain ⟨_, _, _, eq, _⟩ := NodeState.recordCommit_eq node state index
  rw [eq]

/-- Extending a log cannot move its bounded committable frontier backwards. -/
private lemma maxCommittableIndexUpTo_mono {left right : List Entry}
    (isPrefix : left <+: right) (frontier : Nat)
    : maxCommittableIndexUpTo left frontier <= maxCommittableIndexUpTo right frontier :=
  maxCommittableIndex_le_of_prefix
    (List.prefix_take_iff.mpr
      ⟨(List.take_prefix _ _).trans isPrefix, List.length_take_le _ _⟩)

/-- The follower append loop changes only the log, commit and retirement
fields, and may clear the role. -/
private lemma fromLeader_loop (self : NodeID) (limit : Nat) (entries : List Entry)
    : forall (state : NodeState),
        exists commitIndex retiredCommittedIndex role primaryKnown,
          entries.foldl
              (fun state entry =>
                let state := { state with log := state.log ++ [entry] }
                if entry.content.isSignature then
                  state.recordCommit self
                    (max state.commitIndex (maxCommittableIndexUpTo state.log limit))
                else
                  state)
              state
            = {
              state with
                log := state.log ++ entries,
                commitIndex,
                retiredCommittedIndex,
                role,
                primaryKnown
            }
          /\ (role = state.role \/ role = .none)
          /\ state.commitIndex <= commitIndex
          /\ commitIndex
              <= max state.commitIndex
                  (maxCommittableIndexUpTo (state.log ++ entries) limit) := by
  induction entries with
  | nil =>
      intro state
      exact ⟨
        state.commitIndex,
        state.retiredCommittedIndex,
        state.role,
        state.primaryKnown,
        by simp,
        Or.inl rfl,
        Nat.le.refl,
        Nat.le_max_left _ _
      ⟩
  | cons entry entries ih =>
      intro state
      simp only [List.foldl_cons]
      have mono :=
        maxCommittableIndexUpTo_mono (List.prefix_append (state.log ++ [entry]) entries) limit
      simp only [List.append_assoc, List.cons_append, List.nil_append] at mono
      by_cases signature : entry.content.isSignature
      · simp only [signature, ↓reduceIte]
        obtain ⟨retired₀, role₀, known₀, eq₀, roleCase₀⟩ :=
          NodeState.recordCommit_eq self { state with log := state.log ++ [entry] }
            (max state.commitIndex
              (maxCommittableIndexUpTo (state.log ++ [entry]) limit))
        rw [eq₀]
        obtain ⟨commitIndex, retired, role, known, eq, roleCase, lower, upper⟩ := ih _
        rw [eq]
        simp only [List.append_assoc, List.cons_append, List.nil_append] at lower upper roleCase ⊢
        refine ⟨commitIndex, retired, role, known, rfl, ?_,
          Nat.le_trans (Nat.le_max_left _ _) lower,
          Nat.le_trans upper (Nat.max_le.mpr ⟨Nat.max_le.mpr ⟨Nat.le_max_left _ _,
            Nat.le_trans mono (Nat.le_max_right _ _)⟩, Nat.le_max_right _ _⟩)⟩
        rcases roleCase with same | none
        · rw [same]
          exact roleCase₀
        · exact Or.inr none
      · simp only [signature, Bool.false_eq_true, ↓reduceIte]
        obtain ⟨commitIndex, retired, role, known, eq, roleCase, lower, upper⟩ := ih _
        rw [eq]
        simp only [List.append_assoc, List.cons_append, List.nil_append] at lower upper roleCase ⊢
        exact ⟨commitIndex, retired, role, known, rfl, roleCase, lower, upper⟩

/--
Intermediate commits use prefixes of the final log, so the follower's final
commit index is the bounded committable frontier of the extended log.
-/
private lemma handleAppendEntiresFromPrimary_eq (self : NodeID) (state : NodeState)
    (request : AppendEntriesRequest)
    : let log :=
        state.log ++ request.entries.drop (state.log.length - request.prevLogIndex)
      exists retiredCommittedIndex role primaryKnown,
        handleAppendEntiresFromPrimary self state request
          = (
            {
              state with
                log
                commitIndex :=
                  max state.commitIndex
                    (maxCommittableIndexUpTo log
                      (min request.primaryCommit
                        (request.prevLogIndex + request.entries.length)))
                retiredCommittedIndex
                role
                primaryKnown
            },
            {
              term := state.currentTerm
              success := true
              lastLogIndex := request.prevLogIndex + request.entries.length
            }
          )
        /\ (role = state.role \/ role = .none) := by
  intro log
  obtain ⟨commitIndex, retired, role, known, eq, roleCase, lower, upper⟩ :=
    fromLeader_loop self
      (min request.primaryCommit (request.prevLogIndex + request.entries.length))
      (request.entries.drop (state.log.length - request.prevLogIndex)) state
  unfold handleAppendEntiresFromPrimary
  dsimp only
  rw [eq]
  obtain ⟨retired', role', known', eq', roleCase'⟩ := NodeState.recordCommit_eq self _ _
  rw [eq']
  refine ⟨retired', role', known', ?_, ?_⟩
  · simp only [log]
    congr 2
    exact Nat.le_antisymm (Nat.max_le.mpr ⟨upper, Nat.le_max_right _ _⟩)
      (Nat.max_le.mpr ⟨Nat.le_trans lower (Nat.le_max_left _ _), Nat.le_max_right _ _⟩)
  · rcases roleCase' with same | none
    · rw [same]
      exact roleCase
    · exact Or.inr none

/-- A rollback point lies after the request's previous index. -/
private lemma firstTermConflictIndex_ge {state : NodeState}
    {request : AppendEntriesRequest} {index : Nat}
    (conflict : firstTermConflictIndex state request = some index)
    : request.prevLogIndex + 1 <= index := by
  unfold firstTermConflictIndex at conflict
  obtain ⟨pair, found, rfl⟩ := Option.map_eq_some_iff.mp conflict
  obtain ⟨_, offset, lt, rfl, _⟩ := List.find?_eq_some_iff_getElem.mp found
  simp

end Consensus.Proofs.Ledger

namespace Consensus.Proofs.Direct

set_option linter.unusedSectionVars false
open Consensus.Proofs.Config
open CCF CCF.MultiNodeTransitionSystem Concrete
open Model.Node
open Model (initialNodeState)
variable [Config.InitialConfiguration]

private theorem NodeInvariant.reachable {P : NodeID -> NodeState -> Prop}
    (invariant : NodeInvariant P) {nodes : List NodeID} {state : Model.State}
    (reachable
      : (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes).Reachable state)
    : forall node local_, (node, local_) ∈ state.nodes -> P node local_ := by
  induction reachable
    using @TransitionSystem.Reachable.rec
      (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes) with
  | initial initialized =>
      intro node local_ member
      have initial : local_ = initialNodeState Config.INITIAL_CONFIGURATION node := initialized.2.2.2.2 (node, local_) member
      subst initial
      exact invariant.initial node
  | @step before after action _ stepped ih =>
      have preserved : forall {actor : NodeID} {old : NodeState}
          {event : Model.Node.Event} {new outputs},
          nodeState before actor = some old ->
          (Model.Node.step (Capabilities.record actor) actor old event).run {}
            = some (new, outputs) ->
          forall node local_,
            (node, local_) ∈ replaceNode before.nodes actor new ->
            P node local_ := by
        intro actor old event new outputs found acted node local_ member
        rcases mem_replaceNode member with ⟨rfl, rfl⟩ | ⟨_, listed⟩
        · exact invariant.step _ _ _ _ _ (ih _ _ (mem_of_nodeState found)) acted
        · exact ih _ _ listed
      cases action with
      | «local» actor input =>
          obtain ⟨old, new, outputs, found, acted, rfl⟩ := step_local stepped
          exact preserved (event := .internal input) found
            (by cases input <;> exact acted)
      | deliver envelope =>
          obtain ⟨_, old, new, outputs, found, received, rfl⟩ := step_deliver stepped
          exact preserved (event := .receive envelope.source envelope.payload) found received

private theorem find_of_mem {entries : List (NodeID × NodeState)} {node : NodeID}
    {local_ : NodeState} (distinct : (entries.map Prod.fst).Nodup)
    (member : (node, local_) ∈ entries)
    : entries.find? (fun entry => entry.1 == node) = some (node, local_) := by
  induction entries with
  | nil => simp at member
  | cons head tail ih =>
      obtain ⟨key, value⟩ := head
      simp only [List.map_cons, List.nodup_cons] at distinct
      by_cases here : key = node
      · subst here
        rcases List.mem_cons.mp member with same | later
        · rw [same]
          simp
        · exact absurd (List.mem_map.mpr ⟨_, later, rfl⟩) distinct.1
      · rcases List.mem_cons.mp member with same | later
        · simp only [Prod.mk.injEq] at same
          exact absurd same.1.symm here
        · simp [here, ih distinct.2 later]

private theorem nodeState_of_mem {state : Model.State} {node : NodeID}
    {local_ : NodeState} (distinct : (state.nodes.map Prod.fst).Nodup)
    (member : (node, local_) ∈ state.nodes)
    : nodeState state node = some local_ := by
  simp [nodeState, find_of_mem distinct member]

end Consensus.Proofs.Direct

namespace Consensus.Proofs.Direct.Keeps

set_option linter.unusedSectionVars false
open CCF
variable {Node Message Notification : Type}
variable {α β : Type}

private theorem pure' {P : α -> Prop} {value : α} (holds : P value)
    : Keeps (Node := Node) (Message := Message) (Notification := Notification) P
        (pure value) := by
  intro _ _ _ ran
  cases ran
  exact holds

private theorem trivial' (m : Effect Node Message Notification α)
    : Keeps (fun _ => True) m :=
  fun _ _ _ _ => True.intro

private theorem bind' {Q : α -> Prop} {P : β -> Prop}
    {m : Effect Node Message Notification α} {f : α -> Effect Node Message Notification β}
    (first : Keeps Q m) (rest : forall value, Q value -> Keeps P (f value))
    : Keeps P (m >>= f) := by
  intro outputs result after ran
  simp only [StateT.run_bind] at ran
  cases ranFirst : m.run outputs with
  | none => simp [ranFirst] at ran
  | some pair =>
      obtain ⟨value, middle⟩ := pair
      simp only [ranFirst] at ran
      exact rest value (first _ _ _ ranFirst) _ _ _ ran

private theorem seq' {P : β -> Prop} {m : Effect Node Message Notification α}
    {f : α -> Effect Node Message Notification β}
    (rest : forall value, Keeps P (f value))
    : Keeps P (m >>= f) :=
  bind' (trivial' m) fun value _ => rest value

private theorem mono {P Q : α -> Prop} {m : Effect Node Message Notification α}
    (kept : Keeps P m) (weaker : forall value, P value -> Q value)
    : Keeps Q m :=
  fun outputs result after ran => weaker _ (kept outputs result after ran)

private theorem ite' {P : α -> Prop} {c : Prop} [Decidable c]
    {m n : Effect Node Message Notification α}
    (yes : c -> Keeps P m) (no : Not c -> Keeps P n)
    : Keeps P (if c then m else n) := by
  split
  · exact yes ‹_›
  · exact no ‹_›

private theorem foldlM' {γ : Type} {P : α -> Prop}
    {f : α -> γ -> Effect Node Message Notification α}
    (step : forall value item, P value -> Keeps P (f value item))
    : forall (items : List γ) (init : α), P init -> Keeps P (items.foldlM f init)
  | [], _, holds => by simpa using pure' holds
  | item :: items, init, holds => by
      simp only [List.foldlM_cons]
      exact bind' (step init item holds) fun value kept => foldlM' step items value kept

end Consensus.Proofs.Direct.Keeps

namespace Consensus.Proofs.Direct

set_option linter.unusedSectionVars false
open Consensus.Proofs.Config
open CCF
open Model.Node
open Ledger (
  isSignatureAt_of_prefix isSignatureAt_take_of_le signatureIndex_le_maxCommittableIndex
    maxCommittableIndexUpTo_le_length maxCommittableIndexUpToPositiveIsSignature
  )

private theorem CommitFrontier.of_log {state after : NodeState}
    (frontier : CommitFrontier state) (logEq : after.log = state.log)
    (commitEq : after.commitIndex = state.commitIndex)
    : CommitFrontier after := by
  unfold CommitFrontier at *
  rw [logEq, commitEq]
  exact frontier

private theorem CommitFrontier.extend {state : NodeState}
    (frontier : CommitFrontier state) {log : List Entry}
    (extends_ : state.log <+: log)
    : CommitFrontier { state with log } := by
  refine ⟨frontier.1.trans extends_.length_le, fun positive => ?_⟩
  exact isSignatureAt_of_prefix extends_ (frontier.2 positive)

private theorem CommitFrontier.keep {state : NodeState}
    (frontier : CommitFrontier state) {count : Nat} (within : state.commitIndex <= count)
    {suffix : List Entry}
    : CommitFrontier { state with log := state.log.take count ++ suffix } := by
  refine ⟨?_, fun positive => ?_⟩
  · simp only [List.length_append, List.length_take]
    exact Nat.le_trans (Nat.le_min.mpr ⟨within, frontier.1⟩) (Nat.le_add_right _ _)
  · exact isSignatureAt_of_prefix (List.prefix_append _ _)
      (isSignatureAt_take_of_le within (frontier.2 positive))

/-- A new commit frontier chosen from the latest covered signature. -/
private theorem CommitFrontier.advance {state : NodeState}
    {log : List Entry} {bound : Nat}
    (extends_ : CommitFrontier { state with log })
    : CommitFrontier
        {
          state with
            log, commitIndex := max state.commitIndex (maxCommittableIndexUpTo log bound)
        } := by
  refine ⟨Nat.max_le.mpr ⟨extends_.1, maxCommittableIndexUpTo_le_length log bound⟩,
    fun positive => ?_⟩
  simp only at positive ⊢
  rcases Nat.le_total state.commitIndex (maxCommittableIndexUpTo log bound) with le | le
  · rw [Nat.max_eq_right le] at positive ⊢
    exact maxCommittableIndexUpToPositiveIsSignature positive
  · rw [Nat.max_eq_left le] at positive ⊢
    exact extends_.2 positive

private theorem foldl_select_max (P : Nat -> Prop) [DecidablePred P] (values : List Nat)
    (init : Nat)
    : values.foldl (fun best index => if P index then max best index else best) init
        = init
      \/ P
          (values.foldl (fun best index => if P index then max best index else best)
            init) := by
  induction values generalizing init with
  | nil => exact Or.inl rfl
  | cons head tail ih =>
      simp only [List.foldl_cons]
      rcases ih (if P head then max init head else init) with same | holds
      · rw [same]
        by_cases chosen : P head
        · rcases Nat.le_total init head with le | le
          · right
            simp [chosen, Nat.max_eq_right le]
          · left
            simp [chosen, Nat.max_eq_left le]
        · simp [chosen]
      · exact Or.inr holds

private theorem foldl_select_max_pos (P : Nat -> Prop) [DecidablePred P]
    (values : List Nat)
    (positive
      : 0 < values.foldl (fun best index => if P index then max best index else best) 0)
    : P
        (values.foldl (fun best index => if P index then max best index else best)
          0) := by
  rcases foldl_select_max P values 0 with zero | holds
  · rw [zero] at positive
    exact absurd positive (Nat.lt_irrefl 0)
  · exact holds

private theorem highestCommittableIndex_signature (state : NodeState) (self : NodeID)
    (positive : 0 < highestCommittableIndex state self)
    : isSignatureAt state.log (highestCommittableIndex state self) = true := by
  unfold highestCommittableIndex at positive ⊢
  exact (foldl_select_max_pos _ _ positive).2.1

private theorem signature_le_length {log : List Entry} {index : Nat}
    (signature : isSignatureAt log index = true)
    : index <= log.length := by
  obtain ⟨entry, found, _⟩ := Ledger.isSignatureAtTrue signature
  exact Ledger.entryAtSomeIndexBound found

private theorem CommitFrontier.leaderAppendState {state : NodeState}
    (frontier : CommitFrontier state) (content : EntryContent)
    : CommitFrontier
        { state with log := state.log ++ [{ term := state.currentTerm, content }] } :=
  frontier.extend (List.prefix_append _ _)

end Consensus.Proofs.Direct

namespace Consensus.Proofs.Direct

set_option linter.unusedSectionVars false
open Consensus.Proofs.Config
open CCF
open Model.Node
open Ledger (
  isSignatureAt_of_prefix isSignatureAt_take_of_le signatureIndex_le_maxCommittableIndex
    maxCommittableIndexUpTo_le_length maxCommittableIndexUpToPositiveIsSignature
  )
section AppendEntries
variable {self : NodeID} {state : NodeState}
  {request : AppendEntriesRequest}

private theorem CommitFrontier.fromLeader (frontier : CommitFrontier state)
    : CommitFrontier (handleAppendEntiresFromPrimary self state request).1 := by
  obtain ⟨retired, role, known, eq, -⟩ :=
    Ledger.handleAppendEntiresFromPrimary_eq self state request
  rw [eq]
  exact (CommitFrontier.advance
          (bound :=
            min request.primaryCommit (request.prevLogIndex + request.entries.length))
          (frontier.extend (List.prefix_append _ _))).of_log
    rfl rfl

private theorem CommitFrontier.handleAppendEntriesRequest
    (frontier : CommitFrontier state) (caps : Caps) (source : NodeID)
    : Keeps CommitFrontier
        (Model.Node.handleAppendEntriesRequest caps self source state request) := by
  unfold Model.Node.handleAppendEntriesRequest
  have stepped : CommitFrontier (if request.term = state.currentTerm /\
      (state.role = .candidate \/ state.role = .preVoteCandidate) then
        becomeAwareOfNewTerm state request.term else state) := by
    split
    · exact frontier.of_log rfl rfl
    · exact frontier
  generalize (if request.term = state.currentTerm /\
      (state.role = .candidate \/ state.role = .preVoteCandidate) then
        becomeAwareOfNewTerm state request.term else state) = current
    at stepped
  refine Keeps.ite' (fun _ => by
    dsimp only
    split <;> exact Keeps.seq' fun _ => Keeps.pure' stepped) fun _ => ?_
  dsimp only
  refine Keeps.ite' (fun _ => Keeps.pure' (stepped.of_log rfl rfl)) fun notBefore => ?_
  have within : current.commitIndex <= request.prevLogIndex :=
    Nat.le_of_not_lt fun lt => notBefore (Or.inl lt)
  split
  · exact Keeps.seq' fun _ => Keeps.pure'
      (CommitFrontier.of_log stepped (after := { current with primaryKnown := true }) rfl
        rfl).fromLeader
  · rename_i index conflict
    have := Ledger.firstTermConflictIndex_ge conflict
    exact Keeps.seq' fun _ => Keeps.pure'
      (CommitFrontier.of_log (stepped.keep (count := index - 1)
        (Nat.le_trans within (Nat.le_sub_of_add_le this)) (suffix := []))
        (after :=
          {
            current with
              primaryKnown := true, log := current.log.take (index - 1), isNewFollower := false
          })
        (by simp) rfl).fromLeader

end AppendEntries
end Consensus.Proofs.Direct

namespace Consensus.Proofs.Direct

set_option linter.unusedSectionVars false
open Consensus.Proofs.Config
open CCF
open Model.Node
open Ledger (
  isSignatureAt_of_prefix isSignatureAt_take_of_le signatureIndex_le_maxCommittableIndex
    maxCommittableIndexUpTo_le_length maxCommittableIndexUpToPositiveIsSignature
  )

private theorem CommitFrontier.advanced {state : NodeState} (self : NodeID)
    (frontier : CommitFrontier state) (caps : Caps)
    : Keeps CommitFrontier (Model.Node.advanceCommit caps state self) := by
  unfold Model.Node.advanceCommit
  refine Keeps.ite' (fun _ => Keeps.pure' frontier) fun ahead => ?_
  have signature := highestCommittableIndex_signature state self
    (Nat.lt_of_le_of_lt (Nat.zero_le _) (Nat.lt_of_not_le ahead))
  have advanced : CommitFrontier
      (state.recordCommit self (highestCommittableIndex state self)) :=
    ⟨by simpa using signature_le_length signature, fun _ => by simpa using signature⟩
  dsimp only
  exact Keeps.ite'
    (fun _ =>
      Keeps.ite' (fun _ => Keeps.seq' fun _ => Keeps.pure' advanced)
        fun _ => Keeps.pure' advanced)
    fun _ => Keeps.pure' advanced

private theorem CommitFrontier.withSent {state : NodeState}
    (frontier : CommitFrontier state) {sentIndex : NodeID -> Nat}
    : CommitFrontier { state with sentIndex } :=
  frontier.of_log rfl rfl

/-- The log a new leader keeps: its signed prefix, or everything at startup. -/
private theorem CommitFrontier.promotedLog {state : NodeState}
    (frontier : CommitFrontier state)
    : CommitFrontier
        {
          state with
            log :=
              if state.commitIndex > 0 then
                state.log.take (lastCommittableIndex state)
              else
                state.log
        } := by
  split
  · have kept := frontier.keep (count := lastCommittableIndex state)
      (by unfold lastCommittableIndex; exact Nat.le_max_left _ _) (suffix := [])
    exact kept.of_log (by simp) rfl
  · exact frontier.of_log rfl rfl

end Consensus.Proofs.Direct

namespace Consensus.Proofs.Direct

set_option linter.unusedSectionVars false
open Consensus.Proofs.Config
open CCF
open Model.Node
open Ledger (
  isSignatureAt_of_prefix isSignatureAt_take_of_le signatureIndex_le_maxCommittableIndex
    maxCommittableIndexUpTo_le_length maxCommittableIndexUpToPositiveIsSignature
  )
section Handlers
variable (caps : Caps) (self : NodeID)

private theorem CommitFrontier.appendEntry {state : NodeState}
    (frontier : CommitFrontier state) (content : EntryContent)
    : Keeps CommitFrontier (Model.Node.appendEntry caps self state content) := by
  unfold Model.Node.appendEntry
  simp only [pure_bind]
  repeat'
    first
    | exact Keeps.pure' ((frontier.leaderAppendState content).of_log rfl rfl)
    | refine Keeps.ite' (fun _ => ?_) fun _ => ?_
    | refine Keeps.seq' fun _ => ?_
    | split

private theorem CommitFrontier.becomePrimary {state : NodeState}
    (frontier : CommitFrontier state)
    : Keeps CommitFrontier (Model.Node.becomePrimary caps self state) := by
  unfold Model.Node.becomePrimary
  refine Keeps.bind' (CommitFrontier.advanced self ?_ caps) fun _ kept =>
      Keeps.seq' fun _ => Keeps.pure' kept
  unfold Model.Node.primaryState
  exact frontier.promotedLog.of_log rfl rfl

private theorem CommitFrontier.electIfQuorum {state : NodeState}
    (frontier : CommitFrontier state)
    : Keeps CommitFrontier (Model.Node.electIfQuorum caps self state) := by
  unfold Model.Node.electIfQuorum
  exact Keeps.ite' (fun _ => frontier.becomePrimary caps self) fun _ => Keeps.pure' frontier

private theorem CommitFrontier.becomeCandidate {state : NodeState}
    (frontier : CommitFrontier state)
    : Keeps CommitFrontier (Model.Node.becomeCandidate caps state self) := by
  unfold Model.Node.becomeCandidate
  refine Keeps.bind' (CommitFrontier.electIfQuorum caps self ?_) fun _ kept =>
    Keeps.seq' fun _ => Keeps.pure' kept
  exact frontier.of_log rfl rfl

private theorem CommitFrontier.becomePreVoteCandidate {state : NodeState}
    (frontier : CommitFrontier state)
    : Keeps CommitFrontier (Model.Node.becomePreVoteCandidate caps state self) := by
  unfold Model.Node.becomePreVoteCandidate
  refine Keeps.ite' (fun _ => CommitFrontier.becomeCandidate caps self ?_)
    fun _ => Keeps.seq' fun _ => Keeps.pure' ?_ <;> exact frontier.of_log rfl rfl

/-- Successor nomination only sends; on success it returns its input state. -/
private theorem Keeps.nominateSuccessor (state : NodeState)
    : Keeps (fun result => result = state)
        (Model.Node.nominateSuccessor caps state self) := by
  unfold Model.Node.nominateSuccessor
  refine Keeps.seq' fun _ => ?_
  split
  · exact Keeps.seq' fun _ => Keeps.pure' rfl
  · exact Keeps.pure' rfl

private theorem CommitFrontier.act {state : NodeState}
    (frontier : CommitFrontier state) (input : Input)
    : Keeps CommitFrontier (Model.Node.act caps self state input) := by
  cases input with
  | append entries =>
      unfold Model.Node.act Model.Node.appendBatch
      exact Keeps.seq' fun _ => Keeps.bind'
        (Keeps.foldlM' (fun current entry kept =>
          Keeps.bind' (kept.appendEntry caps self entry.content) fun appended frontier =>
            Keeps.foldlM'
              (fun current (destination, endIndex) kept => by
                unfold Model.Node.sendEntries
                exact Keeps.seq' fun _ => Keeps.seq' fun _ => Keeps.pure' kept.withSent)
              entry.flushes appended frontier)
          entries state frontier)
        fun _ kept => kept.advanced self caps
  | sendEntries destination endIndex =>
      unfold Model.Node.act Model.Node.sendEntries
      exact Keeps.seq' fun _ => Keeps.seq' fun _ => Keeps.pure' frontier.withSent
  | timeout kind =>
      cases kind with
      | election =>
          unfold Model.Node.act Model.Node.startElection
          exact Keeps.seq' fun _ => frontier.becomePreVoteCandidate caps self
      | checkQuorum =>
          unfold Model.Node.act Model.Node.checkQuorum
          exact Keeps.seq' fun _ => Keeps.pure' (frontier.of_log rfl rfl)
  | nominateSuccessor =>
      exact (Keeps.nominateSuccessor caps self state).mono fun _ same => same ▸ frontier

private theorem CommitFrontier.receive {state : NodeState}
    (frontier : CommitFrontier state) (source : NodeID) (message : Message)
    : Keeps CommitFrontier (Model.Node.receive caps self source state message) := by
  have observed : CommitFrontier (observeTerm state message) :=
    frontier.of_log (Concrete.observeTerm_log _ _) (Concrete.observeTerm_commitIndex _ _)
  unfold Model.Node.receive
  refine Keeps.ite' (fun _ => Keeps.pure' frontier) fun _ => ?_
  dsimp only
  generalize observeTerm state message = current at observed ⊢
  cases message with
  | appendEntriesRequest request => exact observed.handleAppendEntriesRequest caps source
  | appendEntriesResponse response =>
      unfold Model.Node.handleAppendEntriesResponse
      refine Keeps.ite' (fun _ => Keeps.pure' observed) fun _ => ?_
      refine Keeps.ite' (fun _ => ?_) fun _ => Keeps.pure' (observed.of_log rfl rfl)
      refine Keeps.ite' (fun _ => CommitFrontier.advanced self ?_ caps)
        fun _ => Keeps.pure' observed
      exact observed.of_log rfl rfl
  | requestVoteRequest request =>
      unfold Model.Node.handleRequestVoteRequest
      exact Keeps.seq' fun _ => Keeps.pure' (by split <;> exact observed.of_log rfl rfl)
  | requestVoteResponse response =>
      unfold Model.Node.handleRequestVoteResponse
      exact Keeps.ite' (fun _ => CommitFrontier.electIfQuorum caps self (observed.of_log rfl rfl))
        fun _ => Keeps.pure' observed
  | requestPreVoteRequest request =>
      unfold Model.Node.handleRequestPreVoteRequest
      exact Keeps.seq' fun _ => Keeps.pure' observed
  | requestPreVoteResponse response =>
      unfold Model.Node.handleRequestPreVoteResponse
      refine Keeps.ite' (fun _ => ?_) fun _ => Keeps.pure' observed
      dsimp only
      exact Keeps.ite' (fun _ => CommitFrontier.becomeCandidate caps self (observed.of_log rfl rfl))
        fun _ => Keeps.pure' (observed.of_log rfl rfl)
  | proposeRequestVoteRequest term =>
      unfold Model.Node.handleProposeRequestVoteRequest
      exact Keeps.ite' (fun _ => CommitFrontier.becomeCandidate caps self observed)
        fun _ => Keeps.pure' observed

end Handlers
end Consensus.Proofs.Direct

namespace Consensus.Proofs.Direct

set_option linter.unusedSectionVars false
open Consensus.Proofs.Config
open CCF
open Model.Node
open Ledger (
  isSignatureAt_of_prefix isSignatureAt_take_of_le signatureIndex_le_maxCommittableIndex
    maxCommittableIndexUpTo_le_length maxCommittableIndexUpToPositiveIsSignature
  )

private theorem commitFrontier_invariant [Config.InitialConfiguration]
    : Direct.NodeInvariant fun _ state => CommitFrontier state := by
  refine ⟨
    fun node =>
      ⟨Nat.zero_le _, fun positive => by simp [Model.initialNodeState] at positive⟩,
    ?_
  ⟩
  intro self state event after outputs frontier stepped
  cases event with
  | internal input =>
      simp only [Model.Node.step] at stepped
      exact frontier.act _ self _ _ _ _ stepped
  | receive source message =>
      simp only [Model.Node.step] at stepped
      exact frontier.receive _ self source message _ _ _ stepped

public theorem committed_frontier_is_signature
    : forall (config : Finset NodeID),
      forall (nodes : List NodeID)
              (trace : CCF.Execution.Trace (Model.transitionSystem config nodes))
              (state : Model.State),
      forall (node : NodeID) (nodeState : NodeState),
        (state ∈ trace /\ (node, nodeState) ∈ state.nodes /\ 0 < nodeState.commitIndex)
        -> isSignatureAt nodeState.log nodeState.commitIndex = true := by
  intro config nodes trace state node nodeState ⟨member, listed, positive⟩
  let _ : Proofs.Config.InitialConfiguration := ⟨config⟩
  exact (Proofs.Direct.commitFrontier_invariant.reachable
          (trace.reachable member) node nodeState listed).2
    positive

end Consensus.Proofs.Direct

namespace Consensus.Proofs.Direct

set_option linter.unusedSectionVars false
open Consensus.Proofs.Config
open CCF CCF.MultiNodeTransitionSystem Concrete
open Model.Node

private theorem Extends.committedLog {before after : NodeState}
    (extended : Extends before after)
    : before.committedLog <+: after.committedLog :=
  List.prefix_take_iff.mpr ⟨extended.2, (List.length_take_le _ _).trans extended.1⟩

private theorem Extends.refl (state : NodeState) : Extends state state :=
  ⟨Nat.le.refl, List.take_prefix _ _⟩

private theorem Extends.trans {first second third : NodeState}
    (left : Extends first second) (right : Extends second third)
    : Extends first third :=
  ⟨left.1.trans right.1, left.committedLog.trans right.2⟩

/-- Keeping the log below `count`, at or above the commit index, and committing no
less extends the committed log. -/
private theorem Extends.of_prefix {before after : NodeState} {count : Nat}
    (within : before.commitIndex <= count) (kept : before.log.take count <+: after.log)
    (grows : before.commitIndex <= after.commitIndex)
    : Extends before after := by
  refine ⟨grows, List.IsPrefix.trans ?_ kept⟩
  unfold NodeState.committedLog
  exact List.take_prefix_take_left within

private theorem Extends.of_log {before after : NodeState}
    (logEq : after.log = before.log) (commitEq : after.commitIndex = before.commitIndex)
    : Extends before after :=
  ⟨commitEq.ge, logEq ▸ List.take_prefix _ _⟩

private theorem Extends.append {state : NodeState} (entry : Entry)
    : Extends state { state with log := state.log ++ [entry] } :=
  ⟨Nat.le.refl, (List.take_prefix _ _).trans (List.prefix_append _ _)⟩

end Consensus.Proofs.Direct

namespace Consensus.Proofs.Direct

set_option linter.unusedSectionVars false
open Consensus.Proofs.Config
open CCF CCF.MultiNodeTransitionSystem Concrete
open Model.Node
section AppendEntries
variable {self : NodeID} {state : NodeState}
  {request : AppendEntriesRequest}

private theorem Extends.fromLeader
    : Extends state (handleAppendEntiresFromPrimary self state request).1 := by
  obtain ⟨retired, role, known, eq, -⟩ :=
    Ledger.handleAppendEntiresFromPrimary_eq self state request
  rw [eq]
  exact ⟨Nat.le_max_left _ _, (List.take_prefix _ _).trans (List.prefix_append _ _)⟩

private theorem Extends.handleAppendEntriesRequest (caps : Caps) (source : NodeID)
    : Keeps (Extends state)
        (Model.Node.handleAppendEntriesRequest caps self source state request) := by
  unfold Model.Node.handleAppendEntriesRequest
  have stepped : Extends state (if request.term = state.currentTerm /\
      (state.role = .candidate \/ state.role = .preVoteCandidate) then
        becomeAwareOfNewTerm state request.term else state) := by
    split
    · exact Extends.of_log rfl rfl
    · exact Extends.refl _
  generalize (if request.term = state.currentTerm /\
      (state.role = .candidate \/ state.role = .preVoteCandidate) then
        becomeAwareOfNewTerm state request.term else state) = current
    at stepped
  refine Keeps.ite' (fun _ => by
    dsimp only
    split <;> exact Keeps.seq' fun _ => Keeps.pure' stepped) fun _ => ?_
  dsimp only
  refine Keeps.ite' (fun _ => Keeps.pure' (stepped.trans (Extends.of_log rfl rfl)))
    fun notBefore => ?_
  have within : current.commitIndex <= request.prevLogIndex :=
    Nat.le_of_not_lt fun lt => notBefore (Or.inl lt)
  split
  · exact Keeps.seq' fun _ => Keeps.pure'
      ((stepped.trans (Extends.of_log (after := { current with primaryKnown := true }) rfl
        rfl)).trans Extends.fromLeader)
  · rename_i index conflict
    have := Ledger.firstTermConflictIndex_ge conflict
    have truncated : Extends current {
        current with
          primaryKnown := true, log := current.log.take (index - 1), isNewFollower := false
      } :=
      Extends.of_prefix (count := index - 1)
        (Nat.le_trans within (Nat.le_sub_of_add_le this)) (List.prefix_refl _) Nat.le.refl
    exact Keeps.seq' fun _ => Keeps.pure' ((stepped.trans truncated).trans Extends.fromLeader)

end AppendEntries
end Consensus.Proofs.Direct

namespace Consensus.Proofs.Direct

set_option linter.unusedSectionVars false
open Consensus.Proofs.Config
open CCF CCF.MultiNodeTransitionSystem Concrete
open Model.Node
section Handlers
variable (caps : Caps) (self : NodeID)

private theorem Extends.advanced (state : NodeState)
    : Keeps (Extends state) (Model.Node.advanceCommit caps state self) := by
  unfold Model.Node.advanceCommit
  refine Keeps.ite' (fun _ => Keeps.pure' (Extends.refl _)) fun ahead => ?_
  have advanced : Extends state
      (state.recordCommit self (highestCommittableIndex state self)) :=
    ⟨by
      rw [Ledger.NodeState.recordCommit_commitIndex]
      exact Nat.le_of_lt (Nat.lt_of_not_le ahead),
      by rw [Ledger.NodeState.recordCommit_log]; exact List.take_prefix _ _⟩
  dsimp only
  exact Keeps.ite'
    (fun _ => Keeps.ite'
      (fun _ => Keeps.seq' fun _ => Keeps.pure' (advanced.trans (Extends.of_log rfl rfl)))
      fun _ => Keeps.pure' (advanced.trans (Extends.of_log rfl rfl)))
    fun _ => Keeps.pure' advanced

private theorem Extends.appendEntry (state : NodeState) (content : EntryContent)
    : Keeps (Extends state) (Model.Node.appendEntry caps self state content) := by
  unfold Model.Node.appendEntry
  simp only [pure_bind]
  repeat'
    first
    | exact Keeps.pure' ((Extends.append _).trans (Extends.of_log rfl rfl))
    | refine Keeps.ite' (fun _ => ?_) fun _ => ?_
    | refine Keeps.seq' fun _ => ?_
    | split

private theorem Extends.becomePrimary (state : NodeState)
    : Keeps (Extends state) (Model.Node.becomePrimary caps self state) := by
  unfold Model.Node.becomePrimary Model.Node.primaryState
  have promoted : Extends state
      {
        state with
          role := .primary
          log :=
            if state.commitIndex > 0 then state.log.take (lastCommittableIndex state)
            else state.log
          primaryKnown := true
          sentIndex := fun _ =>
            (if state.commitIndex > 0 then state.log.take (lastCommittableIndex state)
              else state.log).length
          matchIndex := fun _ => 0
      } := by
    split
    · exact Extends.of_prefix (by unfold lastCommittableIndex; exact Nat.le_max_left _ _)
        (List.prefix_refl _) Nat.le.refl
    · exact Extends.of_log rfl rfl
  exact Keeps.bind' (Extends.advanced caps self _) fun _ kept =>
    Keeps.seq' fun _ => Keeps.pure' (promoted.trans kept)

private theorem Extends.electIfQuorum (state : NodeState)
    : Keeps (Extends state) (Model.Node.electIfQuorum caps self state) := by
  unfold Model.Node.electIfQuorum
  exact Keeps.ite' (fun _ => Extends.becomePrimary caps self state)
    fun _ => Keeps.pure' (Extends.refl _)

private theorem Extends.becomeCandidate (state : NodeState)
    : Keeps (Extends state) (Model.Node.becomeCandidate caps state self) := by
  unfold Model.Node.becomeCandidate
  exact Keeps.bind' (Extends.electIfQuorum caps self _) fun _ kept =>
    Keeps.seq' fun _ => Keeps.pure' ((Extends.of_log rfl rfl).trans kept)

private theorem Extends.becomePreVoteCandidate (state : NodeState)
    : Keeps (Extends state) (Model.Node.becomePreVoteCandidate caps state self) := by
  unfold Model.Node.becomePreVoteCandidate
  refine Keeps.ite' (fun _ => ?_) fun _ => Keeps.seq' fun _ =>
    Keeps.pure' (Extends.of_log rfl rfl)
  exact (Extends.becomeCandidate caps self _).mono fun _ kept =>
    (Extends.of_log rfl rfl).trans kept

private theorem Extends.act (state : NodeState) (input : Input)
    : Keeps (Extends state) (Model.Node.act caps self state input) := by
  cases input with
  | append entries =>
      unfold Model.Node.act Model.Node.appendBatch
      refine Keeps.seq' fun _ => ?_
      exact Keeps.bind'
        (Keeps.foldlM' (P := Extends state) (fun current entry kept =>
          Keeps.bind' (Extends.appendEntry caps self current entry.content)
            fun appended next => Keeps.foldlM'
              (fun current (destination, endIndex) kept => by
                unfold Model.Node.sendEntries
                exact Keeps.seq' fun _ => Keeps.seq' fun _ => Keeps.pure' kept)
              entry.flushes appended (kept.trans next))
          entries state (Extends.refl _))
        fun current kept => (Extends.advanced caps self current).mono fun _ next =>
          kept.trans next
  | sendEntries destination endIndex =>
      unfold Model.Node.act Model.Node.sendEntries
      exact Keeps.seq' fun _ => Keeps.seq' fun _ => Keeps.pure' (Extends.of_log rfl rfl)
  | timeout kind =>
      cases kind with
      | election =>
          unfold Model.Node.act Model.Node.startElection
          exact Keeps.seq' fun _ => Extends.becomePreVoteCandidate caps self state
      | checkQuorum =>
          unfold Model.Node.act Model.Node.checkQuorum
          exact Keeps.seq' fun _ => Keeps.pure' (Extends.of_log rfl rfl)
  | nominateSuccessor =>
      exact (Keeps.nominateSuccessor caps self state).mono fun _ same =>
        same ▸ Extends.of_log rfl rfl

private theorem Extends.receive (state : NodeState) (source : NodeID) (message : Message)
    : Keeps (Extends state) (Model.Node.receive caps self source state message) := by
  have observedExtends : Extends state (observeTerm state message) :=
    Extends.of_log (Concrete.observeTerm_log _ _) (Concrete.observeTerm_commitIndex _ _)
  unfold Model.Node.receive
  refine Keeps.ite' (fun _ => Keeps.pure' (Extends.refl _)) fun _ => ?_
  dsimp only
  generalize observeTerm state message = current at observedExtends ⊢
  refine Keeps.mono (P := Extends current) ?_ fun _ next => observedExtends.trans next
  cases message with
  | appendEntriesRequest request =>
      exact Extends.handleAppendEntriesRequest caps source
  | appendEntriesResponse response =>
      unfold Model.Node.handleAppendEntriesResponse
      refine Keeps.ite' (fun _ => Keeps.pure' (Extends.refl _)) fun _ => ?_
      refine Keeps.ite' (fun _ => ?_) fun _ => Keeps.pure' (Extends.of_log rfl rfl)
      refine Keeps.ite' (fun _ => ?_) fun _ => Keeps.pure' (Extends.refl _)
      exact (Extends.advanced caps self _).mono fun _ next =>
        (Extends.of_log rfl rfl).trans next
  | requestVoteRequest request =>
      unfold Model.Node.handleRequestVoteRequest
      exact Keeps.seq' fun _ => Keeps.pure' (by split <;> exact Extends.of_log rfl rfl)
  | requestVoteResponse response =>
      unfold Model.Node.handleRequestVoteResponse
      refine Keeps.ite' (fun _ => ?_) fun _ => Keeps.pure' (Extends.refl _)
      exact (Extends.electIfQuorum caps self _).mono fun _ next =>
        (Extends.of_log rfl rfl).trans next
  | requestPreVoteRequest request =>
      unfold Model.Node.handleRequestPreVoteRequest
      exact Keeps.seq' fun _ => Keeps.pure' (Extends.refl _)
  | requestPreVoteResponse response =>
      unfold Model.Node.handleRequestPreVoteResponse
      refine Keeps.ite' (fun _ => ?_) fun _ => Keeps.pure' (Extends.refl _)
      dsimp only
      refine Keeps.ite' (fun _ => ?_) fun _ => Keeps.pure' (Extends.of_log rfl rfl)
      exact (Extends.becomeCandidate caps self _).mono fun _ next =>
        (Extends.of_log rfl rfl).trans next
  | proposeRequestVoteRequest term =>
      unfold Model.Node.handleProposeRequestVoteRequest
      exact Keeps.ite' (fun _ => Extends.becomeCandidate caps self current)
        fun _ => Keeps.pure' (Extends.refl _)

end Handlers
end Consensus.Proofs.Direct

namespace Consensus.Proofs.Direct

set_option linter.unusedSectionVars false
open Consensus.Proofs.Config
open CCF CCF.MultiNodeTransitionSystem Concrete
open Model.Node
section Global
variable [Config.InitialConfiguration]

/-- From any state with distinct node identifiers, a step keeps every other node's
state and extends the actor's committed log. -/
private theorem committed_log_step {nodes : List NodeID} {before after : Model.State}
    {action : Model.Action}
    (distinct : (before.nodes.map Prod.fst).Nodup)
    (stepped
      : (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes).step before action
        = some after)
    {node : NodeID} {beforeState afterState : NodeState}
    (beforeMember : (node, beforeState) ∈ before.nodes)
    (afterMember : (node, afterState) ∈ after.nodes)
    : beforeState.committedLog <+: afterState.committedLog := by
  have extended : forall {actor : NodeID} {old : NodeState}
      {new : NodeState},
      nodeState before actor = some old
      -> Extends old new
      -> (node, afterState) ∈ replaceNode before.nodes actor new
      -> beforeState.committedLog <+: afterState.committedLog := by
    intro actor old new found grown member
    rcases mem_replaceNode member with ⟨rfl, rfl⟩ | ⟨_, listed⟩
    · have same : beforeState = old :=
        Option.some.inj ((nodeState_of_mem distinct beforeMember).symm.trans found)
      subst same
      exact grown.committedLog
    · have same : afterState = beforeState :=
        Option.some.inj
          ((nodeState_of_mem distinct listed).symm.trans (nodeState_of_mem distinct beforeMember))
      subst same
      exact List.prefix_refl _
  cases action with
  | «local» actor input =>
      obtain ⟨old, new, outputs, found, acted, rfl⟩ := step_local stepped
      exact extended found (Extends.act _ actor old input _ _ _ acted) afterMember
  | deliver envelope =>
      obtain ⟨_, old, new, outputs, found, received, rfl⟩ := step_deliver stepped
      exact extended found (Extends.receive _ _ old _ _ _ _ _ received) afterMember

end Global
end Consensus.Proofs.Direct

namespace Consensus.Proofs.Direct

set_option linter.unusedSectionVars false
open Consensus.Proofs.Config
open CCF CCF.MultiNodeTransitionSystem Concrete
open Model.Node

public theorem single_node_committed_log_monotonic
    : forall (config : Finset NodeID) (nodes : List NodeID),
      forall (pre post : Model.State),
      forall (nodeId : NodeID) (nodePre nodePost : NodeState),
      forall (action : Model.Action),
        ((pre.nodes.map Prod.fst).Nodup
          /\ (Model.transitionSystem config nodes).step pre action = some post
          /\ (nodeId, nodePre) ∈ pre.nodes
          /\ (nodeId, nodePost) ∈ post.nodes)
        -> nodePre.committedLog <+: nodePost.committedLog := by
  intro config nodes pre post nodeId nodePre nodePost action
    ⟨distinct, stepped, preMember, postMember⟩
  let _ : Proofs.Config.InitialConfiguration := ⟨config⟩
  exact Proofs.Direct.committed_log_step distinct stepped preMember postMember

end Consensus.Proofs.Direct
