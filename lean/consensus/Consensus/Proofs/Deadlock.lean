module

public import Consensus.Model

import all Consensus.Proofs.SafetyInvariant
import Mathlib.Algebra.Order.BigOperators.Group.List
import Mathlib.Algebra.Order.Group.Nat
import Mathlib.Tactic.Lemma

/-!
Deadlock freedom after bootstrapping: once a signature has been committed,
some node can always act.
-/

namespace Consensus.Proofs.Deadlock.Total

open CCF
open Model.Node

/-- `m` never disables the step, whatever has already been emitted. -/
private def Total {α : Type} (m : NodeEffect α) : Prop :=
  forall outputs, (m.run outputs).isSome

private theorem pure' {α : Type} (value : α) : Total (pure value : NodeEffect α) :=
  fun _ => rfl

private theorem bind' {α β : Type} {m : NodeEffect α} {f : α -> NodeEffect β}
    (first : Total m) (rest : forall value, Total (f value))
    : Total (m >>= f) := by
  intro outputs
  simp only [StateT.run_bind]
  obtain ⟨⟨value, middle⟩, ran⟩ := Option.isSome_iff_exists.mp (first outputs)
  simp only [ran]
  exact rest value middle

private theorem send (self target : NodeID) (payload : Message)
    : Total ((Capabilities.record self).send payload target) := by
  intro outputs
  simp [Capabilities.record, modify, modifyGet, StateT.run]
  rfl

private theorem ite' {α : Type} {c : Prop} [Decidable c] {m n : NodeEffect α}
    (yes : c -> Total m) (no : Not c -> Total n)
    : Total (if c then m else n) := by
  split
  · exact yes ‹_›
  · exact no ‹_›

private theorem guard_bind {α : Type} {c : Prop} [Decidable c] {m : NodeEffect α}
    (holds : c) (rest : Total m)
    : Total (guard c >>= fun _ => m) := by
  intro outputs
  simpa [guard, holds] using rest outputs

private theorem forIn' {β γ : Type} {items : List γ} {init : β}
    {f : γ -> β -> NodeEffect (ForInStep β)}
    (each : forall item value, Total (f item value))
    : Total (forIn items init f) := by
  induction items generalizing init with
  | nil => exact pure' init
  | cons head tail ih =>
      rw [List.forIn_cons]
      refine bind' (each head init) fun step => ?_
      cases step with
      | done value => exact pure' value
      | yield value => exact ih

end Consensus.Proofs.Deadlock.Total

namespace Consensus.Proofs.Deadlock.Total

open CCF
open Model.Node
variable (self : NodeID)

private theorem nominateSuccessor (state : NodeState) (primary : state.role = .primary)
    : Total (Model.Node.nominateSuccessor (Capabilities.record self) state self) := by
  unfold Model.Node.nominateSuccessor
  refine guard_bind primary ?_
  split
  · exact bind' (send _ _ _) fun _ => pure' _
  · exact pure' _

private theorem advanceCommit (state : NodeState)
    : Total (Model.Node.advanceCommit (Capabilities.record self) state self) := by
  unfold Model.Node.advanceCommit
  refine ite' (fun _ => pure' _) fun _ => ?_
  refine ite' (fun _ => ?_) fun _ => pure' _
  refine ite' (fun primary => ?_) fun _ => pure' _
  exact bind' (nominateSuccessor self state primary) fun _ => pure' _

private theorem broadcastToOthers (state : NodeState) (message : Message)
    : Total
        (Model.Node.broadcastToOthers (Capabilities.record self) self state message) := by
  unfold Model.Node.broadcastToOthers
  exact bind' (forIn' fun _ _ => bind' (send _ _ _) fun _ => pure' _) fun _ => pure' _

private theorem becomePrimary (state : NodeState)
    : Total (Model.Node.becomePrimary (Capabilities.record self) self state) := by
  unfold Model.Node.becomePrimary
  exact bind' (advanceCommit self _) fun _ =>
    bind' (forIn' fun _ _ => bind' (send _ _ _) fun _ => pure' _) fun _ => pure' _

private theorem electIfQuorum (state : NodeState)
    : Total (Model.Node.electIfQuorum (Capabilities.record self) self state) := by
  unfold Model.Node.electIfQuorum
  exact ite' (fun _ => becomePrimary self _) fun _ => pure' _

private theorem becomeCandidate (state : NodeState)
    : Total (Model.Node.becomeCandidate (Capabilities.record self) state self) := by
  unfold Model.Node.becomeCandidate
  exact bind' (electIfQuorum self _) fun _ =>
    bind' (broadcastToOthers self _ _) fun _ => pure' _

private theorem becomePreVoteCandidate (state : NodeState)
    : Total
        (Model.Node.becomePreVoteCandidate (Capabilities.record self) state self) := by
  unfold Model.Node.becomePreVoteCandidate
  exact ite' (fun _ => becomeCandidate self _) fun _ =>
    bind' (broadcastToOthers self _ _) fun _ => pure' _

private theorem startElection (state : NodeState) (eligible : canStartElection state self)
    : Total (Model.Node.startElection (Capabilities.record self) state self) := by
  unfold Model.Node.startElection
  exact guard_bind eligible (becomePreVoteCandidate self _)

end Consensus.Proofs.Deadlock.Total

namespace Consensus.Proofs.Deadlock

open CCF CCF.MultiNodeTransitionSystem
open Model.Node

/-- A local input that the node's step accepts is an enabled global action. -/
private theorem enabled_of_total {config : Finset NodeID} {nodes : List NodeID}
    {state : Model.State} {node : NodeID} {local_ : NodeState} {input : Input}
    (distinct : (state.nodes.map Prod.fst).Nodup) (member : (node, local_) ∈ state.nodes)
    (total
      : Total.Total
          (Model.Node.step (Capabilities.record node) node local_ (.internal input)))
    : exists action nextState,
        (Model.transitionSystem config nodes).step state action = some nextState := by
  obtain ⟨⟨after, outputs⟩, ran⟩ := Option.isSome_iff_exists.mp (total {})
  refine ⟨.local node input, {
    nodes := state.nodes.map fun entry => if entry.1 == node then (node, after) else entry
    network := state.network ++ outputs.outgoing
  }, ?_⟩
  let _ : Config.InitialConfiguration := ⟨config⟩
  have found := Direct.nodeState_of_mem distinct member
  simp only [Model.transitionSystem, lift, next, Model.protocol]
  simp [found, ran]

/-- A primary can always nominate a successor; an eligible node can campaign. -/
private theorem enabled_of_member {config : Finset NodeID} {nodes : List NodeID}
    {state : Model.State} {node : NodeID} {local_ : NodeState}
    (distinct : (state.nodes.map Prod.fst).Nodup) (member : (node, local_) ∈ state.nodes)
    (acts : local_.role = .primary \/ canStartElection local_ node)
    : exists action nextState,
        (Model.transitionSystem config nodes).step state action = some nextState := by
  rcases acts with primary | eligible
  · exact enabled_of_total distinct member (input := .nominateSuccessor)
      (Total.nominateSuccessor node local_ primary)
  · exact enabled_of_total distinct member (input := .timeout .election)
      (Total.startElection node local_ eligible)

end Consensus.Proofs.Deadlock

namespace Consensus.Proofs.Deadlock

open CCF
open Model.Node

private theorem mem_retiredCommittedNodes_foldl {node : NodeID} (log : List Entry)
    (init : Finset NodeID)
    : node
        ∈ log.foldl
            (fun retired entry =>
              retired ∪ entry.content.metadata.retirementConfirmations)
            init
      <-> node ∈ init
          \/ exists entry,
              entry ∈ log /\ node ∈ entry.content.metadata.retirementConfirmations := by
  induction log generalizing init with
  | nil => simp
  | cons head tail ih =>
      simp only [List.foldl_cons, ih, Finset.mem_union, List.mem_cons]
      constructor
      · rintro ((old | new) | ⟨entry, member, confirmed⟩)
        · exact Or.inl old
        · exact Or.inr ⟨head, Or.inl rfl, new⟩
        · exact Or.inr ⟨entry, Or.inr member, confirmed⟩
      · rintro (old | ⟨entry, rfl | member, confirmed⟩)
        · exact Or.inl (Or.inl old)
        · exact Or.inl (Or.inr confirmed)
        · exact Or.inr ⟨entry, member, confirmed⟩

/-- A node is retired-committed by a log exactly when some entry confirms it. -/
private theorem mem_retiredCommittedNodes {node : NodeID} {log : List Entry}
    : node ∈ retiredCommittedNodes log
      <-> exists entry,
            entry ∈ log /\ node ∈ entry.content.metadata.retirementConfirmations := by
  unfold retiredCommittedNodes
  rw [mem_retiredCommittedNodes_foldl]
  simp

private theorem retiredCommittedNodes_mono {left right : List Entry}
    (sub : left <+: right) {node : NodeID} (member : node ∈ retiredCommittedNodes left)
    : node ∈ retiredCommittedNodes right := by
  obtain ⟨entry, inLeft, confirmed⟩ := mem_retiredCommittedNodes.mp member
  exact mem_retiredCommittedNodes.mpr ⟨entry, sub.subset inLeft, confirmed⟩

end Consensus.Proofs.Deadlock

namespace Consensus.Proofs.Deadlock.Local

open CCF
open Model.Node
open Direct (Extends Keeps)

/--
How one step may change a node's retirement latch and role: the committed log
extends, a latch is set only when the committed log confirms the node, and the
role becomes `none` only by that latch.
-/
private def Rel (self : NodeID) (before after : NodeState) : Prop :=
  Extends before after
  /\ (before.retiredCommittedIndex.isSome
      -> after.retiredCommittedIndex = before.retiredCommittedIndex)
  /\ (after.retiredCommittedIndex.isSome
      -> before.retiredCommittedIndex.isSome
          \/ self ∈ retiredCommittedNodes after.committedLog)
  /\ (after.role = .none
      -> (before.role = .none /\ after.currentTerm <= before.currentTerm)
          \/ after.retiredCommittedIndex.isSome)

variable {self : NodeID}

private theorem Rel.refl (state : NodeState) : Rel self state state :=
  ⟨
    Extends.refl _,
    fun _ => rfl,
    fun some => Or.inl some,
    fun none => Or.inl ⟨none, le_rfl⟩
  ⟩

private theorem Rel.trans {first second third : NodeState}
    (left : Rel self first second) (right : Rel self second third)
    : Rel self first third := by
  obtain ⟨extendsLeft, keepLeft, setLeft, roleLeft⟩ := left
  obtain ⟨extendsRight, keepRight, setRight, roleRight⟩ := right
  refine ⟨extendsLeft.trans extendsRight, fun some => ?_, fun some => ?_, fun none => ?_⟩
  · have middle := keepLeft some
    rw [keepRight (middle ▸ some), middle]
  · rcases setRight some with middle | confirmed
    · rcases setLeft middle with old | confirmed
      · exact Or.inl old
      · exact Or.inr (retiredCommittedNodes_mono extendsRight.committedLog confirmed)
    · exact Or.inr confirmed
  · rcases roleRight none with ⟨middleNone, le⟩ | some
    · rcases roleLeft middleNone with ⟨firstNone, le'⟩ | middleSome
      · exact Or.inl ⟨firstNone, le.trans le'⟩
      · exact Or.inr (keepRight middleSome ▸ middleSome)
    · exact Or.inr some

/-- A step that keeps the latch, extends the committed log and does not newly
clear the role. -/
private theorem Rel.of_fields {before after : NodeState} (extended : Extends before after)
    (latch : after.retiredCommittedIndex = before.retiredCommittedIndex)
    (role
      : after.role = .none
        -> before.role = .none /\ after.currentTerm <= before.currentTerm)
    : Rel self before after :=
  ⟨
    extended,
    fun _ => latch,
    fun some => Or.inl (latch ▸ some),
    fun none => Or.inl (role none)
  ⟩

private theorem Rel.same {before after : NodeState} (logEq : after.log = before.log)
    (commitEq : after.commitIndex = before.commitIndex)
    (latch : after.retiredCommittedIndex = before.retiredCommittedIndex)
    (roleEq : after.role = before.role) (termEq : after.currentTerm = before.currentTerm)
    : Rel self before after :=
  Rel.of_fields (Extends.of_log logEq commitEq) latch
    fun none =>
      ⟨roleEq ▸ none, termEq.le⟩

/-- A step whose resulting role is not `none`. -/
private theorem Rel.active {before after : NodeState} (logEq : after.log = before.log)
    (commitEq : after.commitIndex = before.commitIndex)
    (latch : after.retiredCommittedIndex = before.retiredCommittedIndex)
    (role : Not (after.role = .none))
    : Rel self before after :=
  Rel.of_fields (Extends.of_log logEq commitEq) latch fun none => (role none).elim

/-- Being retired-committed requires the retirement latch. -/
private theorem latch_of_retired {state : NodeState}
    (retired : state.isRetiredCommitted self)
    : state.retiredCommittedIndex.isSome := by
  revert retired
  unfold NodeState.isRetiredCommitted NodeState.retirement
  dsimp only
  split
  · simp
  · repeat' split
    all_goals simp_all

private theorem Rel.recordCommit (state : NodeState) {index : Nat}
    (grows : state.commitIndex <= index)
    : Rel self state (state.recordCommit self index) := by
  unfold NodeState.recordCommit
  dsimp only
  have extended : Extends state
      { state with
          commitIndex := index
          retiredCommittedIndex :=
            state.retiredCommittedIndex.orElse fun _ =>
              firstLogIndexAfter (state.log.take index) 0
                fun content => decide (self ∈ content.metadata.retirementConfirmations) } :=
    ⟨grows, List.take_prefix _ _⟩
  have latchKeep : state.retiredCommittedIndex.isSome
      -> (state.retiredCommittedIndex.orElse fun _ =>
            firstLogIndexAfter (state.log.take index) 0
              fun content => decide (self ∈ content.metadata.retirementConfirmations))
        = state.retiredCommittedIndex := by
    intro some
    obtain ⟨value, eq⟩ := Option.isSome_iff_exists.mp some
    rw [eq]
    rfl
  have latchSet : (state.retiredCommittedIndex.orElse fun _ =>
        firstLogIndexAfter (state.log.take index) 0
          fun content => decide (self ∈ content.metadata.retirementConfirmations)).isSome
      -> state.retiredCommittedIndex.isSome
          \/ self ∈ retiredCommittedNodes (state.log.take index) := by
    intro some
    cases old : state.retiredCommittedIndex with
    | some _ => exact Or.inl rfl
    | none =>
        right
        rw [old] at some
        simp only [Option.orElse] at some
        obtain ⟨found, eq⟩ := Option.isSome_iff_exists.mp some
        unfold firstLogIndexAfter at eq
        obtain ⟨pair, located, -⟩ := Option.map_eq_some_iff.mp eq
        have holds := List.find?_some located
        have member := List.mem_of_find?_eq_some located
        obtain ⟨entry, position⟩ := pair
        simp only [Bool.and_eq_true, decide_eq_true_eq] at holds
        exact mem_retiredCommittedNodes.mpr
          ⟨entry, List.fst_mem_of_mem_zipIdx member, holds.2⟩
  split
  · next retiring =>
      exact ⟨extended, fun some => latchKeep some, fun some => latchSet some,
        fun _ => Or.inr (latch_of_retired retiring.2)⟩
  · exact ⟨extended, fun some => latchKeep some, fun some => latchSet some,
      fun none => Or.inl ⟨none, le_rfl⟩⟩

end Consensus.Proofs.Deadlock.Local

namespace Consensus.Proofs.Deadlock.Local

open CCF
open Model.Node
open Direct (Extends Keeps)
section Handlers
variable (caps : Caps) (self : NodeID)

private theorem Rel.advanced (state : NodeState)
    : Keeps (Rel self state) (Model.Node.advanceCommit caps state self) := by
  unfold Model.Node.advanceCommit
  refine Keeps.ite' (fun _ => Keeps.pure' (Rel.refl _)) fun ahead => ?_
  have advanced : Rel self state (state.recordCommit self (highestCommittableIndex state self)) :=
    Rel.recordCommit state (Nat.le_of_lt (Nat.lt_of_not_le ahead))
  dsimp only
  exact Keeps.ite'
    (fun _ => Keeps.ite' (fun _ => Keeps.seq' fun _ => Keeps.pure' advanced)
      fun _ => Keeps.pure' advanced)
    fun _ => Keeps.pure' advanced

private theorem Rel.appendEntry (state : NodeState) (content : EntryContent)
    : Keeps (Rel self state) (Model.Node.appendEntry caps self state content) := by
  unfold Model.Node.appendEntry
  simp only [pure_bind]
  repeat'
    first
    | exact Keeps.pure' (Rel.of_fields
        ((Extends.append _).trans (Extends.of_log rfl rfl)) rfl
        fun none => ⟨none, le_rfl⟩)
    | refine Keeps.ite' (fun _ => ?_) fun _ => ?_
    | refine Keeps.seq' fun _ => ?_
    | split

private theorem Rel.becomePrimary (state : NodeState)
    : Keeps (Rel self state) (Model.Node.becomePrimary caps self state) := by
  unfold Model.Node.becomePrimary Model.Node.primaryState
  have promoted : Rel self state
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
    refine Rel.of_fields ?_ rfl fun none => nomatch none
    split
    · exact Extends.of_prefix (by unfold lastCommittableIndex; exact Nat.le_max_left _ _)
        (List.prefix_refl _) le_rfl
    · exact Extends.of_log rfl rfl
  exact Keeps.bind' (Rel.advanced caps self _) fun _ kept =>
    Keeps.seq' fun _ => Keeps.pure' (promoted.trans kept)

private theorem Rel.electIfQuorum (state : NodeState)
    : Keeps (Rel self state) (Model.Node.electIfQuorum caps self state) := by
  unfold Model.Node.electIfQuorum
  exact Keeps.ite' (fun _ => Rel.becomePrimary caps self state)
    fun _ => Keeps.pure' (Rel.refl _)

private theorem Rel.becomeCandidate (state : NodeState)
    : Keeps (Rel self state) (Model.Node.becomeCandidate caps state self) := by
  unfold Model.Node.becomeCandidate
  refine Keeps.bind' (Rel.electIfQuorum caps self _) fun _ kept =>
    Keeps.seq' fun _ => Keeps.pure' (Rel.trans ?_ kept)
  exact Rel.active rfl rfl rfl (by simp)

private theorem Rel.becomePreVoteCandidate (state : NodeState)
    : Keeps (Rel self state) (Model.Node.becomePreVoteCandidate caps state self) := by
  unfold Model.Node.becomePreVoteCandidate
  have pre : Rel self state
      { state with
          role := .preVoteCandidate, primaryKnown := false, preVotesGranted := {self} } :=
    Rel.active rfl rfl rfl (by simp)
  refine Keeps.ite' (fun _ => ?_) fun _ => Keeps.seq' fun _ => Keeps.pure' pre
  exact (Rel.becomeCandidate caps self _).mono fun _ kept => pre.trans kept

private theorem Rel.act (state : NodeState) (input : Input)
    : Keeps (Rel self state) (Model.Node.act caps self state input) := by
  cases input with
  | append entries =>
      unfold Model.Node.act Model.Node.appendBatch
      refine Keeps.seq' fun _ => ?_
      exact Keeps.bind'
        (Keeps.foldlM' (P := Rel self state) (fun current entry kept =>
          Keeps.bind' (Rel.appendEntry caps self current entry.content)
            fun appended next => Keeps.foldlM'
              (fun current (destination, endIndex) kept => by
                unfold Model.Node.sendEntries
                exact Keeps.seq' fun _ => Keeps.seq' fun _ =>
                  Keeps.pure' (kept.trans (Rel.same rfl rfl rfl rfl rfl)))
              entry.flushes appended (kept.trans next))
          entries state (Rel.refl _))
        fun current kept => (Rel.advanced caps self current).mono fun _ next =>
          kept.trans next
  | sendEntries destination endIndex =>
      unfold Model.Node.act Model.Node.sendEntries
      exact Keeps.seq' fun _ => Keeps.seq' fun _ => Keeps.pure' (Rel.same rfl rfl rfl rfl rfl)
  | timeout kind =>
      cases kind with
      | election =>
          unfold Model.Node.act Model.Node.startElection
          exact Keeps.seq' fun _ => Rel.becomePreVoteCandidate caps self state
      | checkQuorum =>
          unfold Model.Node.act Model.Node.checkQuorum
          exact Keeps.seq'
            fun _ =>
              Keeps.pure' (Rel.active rfl rfl rfl (by simp))
  | nominateSuccessor =>
      exact (Direct.Keeps.nominateSuccessor caps self state).mono fun _ same =>
        same ▸ Rel.refl _

/-- The follower append loop, which may record commits after signatures. -/
private theorem Rel.fromLeaderLoop (limit : Nat) (entries : List Entry)
    : forall (state : NodeState),
        Rel self state
          (entries.foldl
            (fun state entry =>
              let state := { state with log := state.log ++ [entry] }
              if entry.content.isSignature then
                state.recordCommit self
                  (max state.commitIndex (maxCommittableIndexUpTo state.log limit))
              else
                state)
            state) := by
  induction entries with
  | nil => intro state; exact Rel.refl _
  | cons entry entries ih =>
      intro state
      simp only [List.foldl_cons]
      have appended : Rel self state { state with log := state.log ++ [entry] } :=
        Rel.of_fields (Extends.append _) rfl fun none => ⟨none, le_rfl⟩
      refine Rel.trans ?_ (ih _)
      split
      · exact appended.trans (Rel.recordCommit _ (Nat.le_max_left _ _))
      · exact appended

private theorem Rel.fromLeader (state : NodeState) (request : AppendEntriesRequest)
    : Rel self state (handleAppendEntiresFromPrimary self state request).1 := by
  unfold handleAppendEntiresFromPrimary
  dsimp only
  exact (Rel.fromLeaderLoop self _ _ state).trans (Rel.recordCommit _ (Nat.le_max_left _ _))

private theorem Rel.handleAppendEntriesRequest (source : NodeID) (state : NodeState)
    (request : AppendEntriesRequest)
    : Keeps (Rel self state)
        (Model.Node.handleAppendEntriesRequest caps self source state request) := by
  unfold Model.Node.handleAppendEntriesRequest
  have stepped : Rel self state (if request.term = state.currentTerm /\
      (state.role = .candidate \/ state.role = .preVoteCandidate) then
        becomeAwareOfNewTerm state request.term else state) := by
    split
    · exact Rel.active rfl rfl rfl (by simp [becomeAwareOfNewTerm])
    · exact Rel.refl _
  generalize (if request.term = state.currentTerm /\
      (state.role = .candidate \/ state.role = .preVoteCandidate) then
        becomeAwareOfNewTerm state request.term else state) = current
    at stepped
  refine Keeps.ite' (fun _ => by
    dsimp only
    split <;> exact Keeps.seq' fun _ => Keeps.pure' stepped) fun _ => ?_
  dsimp only
  refine Keeps.ite'
    (fun _ => Keeps.pure' (stepped.trans (Rel.same rfl rfl rfl rfl rfl)))
    fun notBefore => ?_
  have within : current.commitIndex <= request.prevLogIndex :=
    Nat.le_of_not_lt fun lt => notBefore (Or.inl lt)
  split
  · exact Keeps.seq' fun _ => Keeps.pure'
      ((stepped.trans (Rel.same (after := { current with primaryKnown := true }) rfl rfl rfl
        rfl rfl)).trans (Rel.fromLeader self _ _))
  · rename_i index conflict
    have := Ledger.firstTermConflictIndex_ge conflict
    have truncated : Rel self current {
        current with
          primaryKnown := true, log := current.log.take (index - 1), isNewFollower := false
      } :=
      Rel.of_fields
        (Extends.of_prefix (count := index - 1)
          (Nat.le_trans within (Nat.le_sub_of_add_le this)) (List.prefix_refl _) le_rfl)
        rfl fun none => ⟨none, le_rfl⟩
    exact Keeps.seq' fun _ =>
      Keeps.pure' ((stepped.trans truncated).trans (Rel.fromLeader self _ _))

private theorem Rel.receive (state : NodeState) (source : NodeID) (message : Message)
    : Keeps (Rel self state) (Model.Node.receive caps self source state message) := by
  have observed : Rel self state (observeTerm state message) := by
    unfold observeTerm updateTerm becomeAwareOfNewTerm
    split
    · exact Rel.refl _
    · split
      · split
        · exact Rel.active rfl rfl rfl (by simp)
        · exact Rel.refl _
      · exact Rel.refl _
    all_goals
      split
      · exact Rel.active rfl rfl rfl (by simp)
      · exact Rel.refl _
  unfold Model.Node.receive
  refine Keeps.ite' (fun _ => Keeps.pure' (Rel.refl _)) fun _ => ?_
  dsimp only
  generalize observeTerm state message = current at observed ⊢
  refine Keeps.mono (P := Rel self current) ?_ fun _ next => observed.trans next
  cases message with
  | appendEntriesRequest request =>
      exact Rel.handleAppendEntriesRequest caps self source current request
  | appendEntriesResponse response =>
      unfold Model.Node.handleAppendEntriesResponse
      refine Keeps.ite' (fun _ => Keeps.pure' (Rel.refl _)) fun _ => ?_
      refine Keeps.ite' (fun _ => ?_) fun _ => Keeps.pure' (Rel.same rfl rfl rfl rfl rfl)
      refine Keeps.ite' (fun _ => ?_) fun _ => Keeps.pure' (Rel.refl _)
      exact (Rel.advanced caps self _).mono fun _ next =>
        (Rel.same rfl rfl rfl rfl rfl).trans next
  | requestVoteRequest request =>
      unfold Model.Node.handleRequestVoteRequest
      exact Keeps.seq'
        fun _ => Keeps.pure' (by split <;> exact Rel.same rfl rfl rfl rfl rfl)
  | requestVoteResponse response =>
      unfold Model.Node.handleRequestVoteResponse
      refine Keeps.ite' (fun _ => ?_) fun _ => Keeps.pure' (Rel.refl _)
      exact (Rel.electIfQuorum caps self _).mono fun _ next =>
        (Rel.same rfl rfl rfl rfl rfl).trans next
  | requestPreVoteRequest request =>
      unfold Model.Node.handleRequestPreVoteRequest
      exact Keeps.seq' fun _ => Keeps.pure' (Rel.refl _)
  | requestPreVoteResponse response =>
      unfold Model.Node.handleRequestPreVoteResponse
      refine Keeps.ite' (fun _ => ?_) fun _ => Keeps.pure' (Rel.refl _)
      dsimp only
      refine Keeps.ite' (fun _ => ?_) fun _ => Keeps.pure' (Rel.same rfl rfl rfl rfl rfl)
      exact (Rel.becomeCandidate caps self _).mono fun _ next =>
        (Rel.same rfl rfl rfl rfl rfl).trans next
  | proposeRequestVoteRequest term =>
      unfold Model.Node.handleProposeRequestVoteRequest
      exact Keeps.ite' (fun _ => Rel.becomeCandidate caps self current)
        fun _ => Keeps.pure' (Rel.refl _)

private theorem Rel.step (state : NodeState) (event : Event)
    : Keeps (Rel self state) (Model.Node.step caps self state event) := by
  cases event with
  | internal input => exact Rel.act caps self state input
  | receive source message => exact Rel.receive caps self state source message

end Handlers
end Consensus.Proofs.Deadlock.Local

namespace Consensus.Proofs.Deadlock.Local

open CCF
open Model.Node
open Direct (Extends Keeps NodeInvariant)

/--
A latched retirement is confirmed by the committed log, and a node without a
role either is latched or has never joined a term.
-/
private def Loc (self : NodeID) (state : NodeState) : Prop :=
  (state.retiredCommittedIndex.isSome -> self ∈ retiredCommittedNodes state.committedLog)
  /\ (state.role = .none -> state.retiredCommittedIndex.isSome \/ state.currentTerm < 2)

private theorem Loc.of_rel {self : NodeID} {before after : NodeState}
    (holds : Loc self before) (rel : Rel self before after)
    : Loc self after := by
  obtain ⟨extended, keep, set, role⟩ := rel
  refine ⟨fun some => ?_, fun none => ?_⟩
  · rcases set some with old | confirmed
    · exact retiredCommittedNodes_mono extended.committedLog (holds.1 old)
    · exact confirmed
  · rcases role none with ⟨beforeNone, le⟩ | some
    · rcases holds.2 beforeNone with old | young
      · exact Or.inl (keep old ▸ old)
      · exact Or.inr (Nat.lt_of_le_of_lt le young)
    · exact Or.inl some

private theorem loc_invariant [Config.InitialConfiguration] : NodeInvariant Loc where
  initial node := by
    refine ⟨fun some => by simp [Model.initialNodeState] at some, fun none => Or.inr ?_⟩
    simp only [Model.initialNodeState] at none ⊢
    split at none
    · simp at none
    · split at none
      · simp at none
      · simp only [*, ite_false]
        decide
  step node state event after outputs holds ran :=
    holds.of_rel (Rel.step (Capabilities.record node) node state event _ _ _ ran)

end Consensus.Proofs.Deadlock.Local

namespace Consensus.Proofs.Deadlock.Logs

open CCF
open Model.Node

/-- An appended entry neither re-adds nor confirms a node outside `removedNodes front`. -/
private def EntryOK (front : List Entry) (entry : Entry) : Prop :=
  (forall nodes,
    entry.content.metadata.configuration = some nodes
    -> Disjoint nodes (removedNodes front))
  /\ entry.content.metadata.retirementConfirmations ⊆ removedNodes front

/-- Every entry of the log is `EntryOK` for the entries before it. -/
private def LogOK (log : List Entry) : Prop :=
  forall n (bound : n < log.length), EntryOK (log.take n) log[n]

private theorem LogOK.nil : LogOK [] := fun _ bound => absurd bound (Nat.not_lt_zero _)

private theorem LogOK.take {log : List Entry} (ok : LogOK log) (count : Nat)
    : LogOK (log.take count) := by
  intro n bound
  have within : n < count := by simp at bound; omega
  have inLog : n < log.length := by simp at bound; omega
  rw [List.take_take, Nat.min_eq_left (Nat.le_of_lt within), List.getElem_take]
  exact ok n inLog

private theorem LogOK.prefix {small large : List Entry} (ok : LogOK large)
    (sub : small <+: large)
    : LogOK small := by
  rw [List.prefix_iff_eq_take.mp sub]
  exact ok.take _

private theorem LogOK.append {log : List Entry} {entry : Entry} (ok : LogOK log)
    (entryOK : EntryOK log entry)
    : LogOK (log ++ [entry]) := by
  intro n bound
  simp only [List.length_append, List.length_singleton] at bound
  rcases Nat.lt_or_ge n log.length with inLog | atEnd
  · rw [List.take_append_of_le_length (Nat.le_of_lt inLog), List.getElem_append_left inLog]
    exact ok n inLog
  · have : n = log.length := by omega
    subst this
    simp only [List.take_left', List.getElem_append_right (Nat.le_refl _), Nat.sub_self,
      List.getElem_cons_zero]
    exact entryOK

private theorem configurationHistory_append (log : List Entry) (entry : Entry)
    : configurationHistory (log ++ [entry])
      = configurationHistory log
        ++ (entry.content.metadata.configuration.map
              fun nodes =>
                ({ index := log.length + 1, nodes } : Configuration)).toList := by
  unfold configurationHistory
  rw [List.zipIdx_append, List.filterMap_append]
  congr 1
  simp only [List.zipIdx_cons, List.zipIdx_nil, List.filterMap_cons, List.filterMap_nil]
  cases entry.content.metadata.configuration <;> simp [Nat.add_comm]

private theorem configurationMembers_append (history : List Configuration)
    (configuration : Configuration)
    : configurationMembers (history ++ [configuration])
      = configurationMembers history ∪ configuration.nodes := by
  unfold configurationMembers
  rw [List.foldl_append]
  rfl

private theorem latestConfigurationMembers_append (history : List Configuration)
    (configuration : Configuration)
    : latestConfigurationMembers (history ++ [configuration]) = configuration.nodes := by
  simp [latestConfigurationMembers]

private theorem removedNodes_append_none {log : List Entry} {entry : Entry}
    (none : entry.content.metadata.configuration = none)
    : removedNodes (log ++ [entry]) = removedNodes log := by
  simp [removedNodes, configurationHistory_append, none]

private theorem removedNodes_append_some {log : List Entry} {entry : Entry}
    {nodes : Finset NodeID} (some : entry.content.metadata.configuration = some nodes)
    : removedNodes (log ++ [entry])
      = (configurationMembers (configurationHistory log) ∪ nodes) \ nodes := by
  simp only [removedNodes, configurationHistory_append, some, Option.map_some,
    Option.toList_some]
  rw [configurationMembers_append, latestConfigurationMembers_append]

/-- A permitted entry never returns a removed node to membership. -/
private theorem removedNodes_grow {log : List Entry} {entry : Entry}
    (entryOK : EntryOK log entry)
    : removedNodes log ⊆ removedNodes (log ++ [entry]) := by
  intro node removed
  cases config : entry.content.metadata.configuration with
  | none => rwa [removedNodes_append_none config]
  | some nodes =>
      rw [removedNodes_append_some config]
      have disjoint := entryOK.1 nodes config
      have absent : node ∉ nodes := fun present =>
        Finset.disjoint_left.mp disjoint present removed
      simp only [removedNodes, Finset.mem_sdiff] at removed
      exact Finset.mem_sdiff.mpr ⟨Finset.mem_union_left _ removed.1, absent⟩

private theorem removedNodes_take_mono {log : List Entry} (ok : LogOK log)
    : forall {small large : Nat},
        small <= large
        -> removedNodes (log.take small) ⊆ removedNodes (log.take large) := by
  intro small large le
  induction le with
  | refl => exact Finset.Subset.refl _
  | @step large _ ih =>
      refine ih.trans ?_
      rcases Nat.lt_or_ge large log.length with inLog | beyond
      · rw [← List.take_concat_get' log large inLog]
        exact removedNodes_grow (ok large inLog)
      · rw [List.take_of_length_le beyond, List.take_of_length_le (by omega)]

/-- Under `LogOK`, a node removed by a prefix stays removed. -/
private theorem removedNodes_prefix {small large : List Entry} (ok : LogOK large)
    (sub : small <+: large)
    : removedNodes small ⊆ removedNodes large := by
  have eq : large.take small.length = small := (List.prefix_iff_eq_take.mp sub).symm
  have grown := removedNodes_take_mono ok sub.length_le
  rwa [eq, List.take_length] at grown

end Consensus.Proofs.Deadlock.Logs

namespace Consensus.Proofs.Deadlock.Logs

open CCF
open Model.Node
open Direct (Keeps)

private theorem guardBind {α : Type} {P : α -> Prop} {c : Prop} [Decidable c]
    {m : NodeEffect α} (rest : c -> Keeps P m)
    : Keeps P (guard c >>= fun _ => m) := by
  intro outputs result after ran
  by_cases holds : c
  · simp only [guard, holds, ite_true] at ran
    exact rest holds outputs result after (by simpa using ran)
  · simp [guard, holds] at ran

/-- Nodes retired by committed configurations are removed in the whole log. -/
private theorem retirementCompleted_removed {state : NodeState} (ok : LogOK state.log)
    : state.retirementCompletedNodes ⊆ removedNodes state.log := by
  intro node member
  simp only [NodeState.retirementCompletedNodes, Finset.mem_sdiff] at member
  have removed : node ∈ removedNodes state.committedLog := by
    simp only [removedNodes, Finset.mem_sdiff]
    exact member.1
  exact removedNodes_prefix ok (List.take_prefix _ _) removed

private theorem entryOK_of {state : NodeState} (ok : LogOK state.log) {term : Nat}
    {content : EntryContent}
    (confirmations
      : content.metadata.retirementConfirmations.Nonempty
        -> content.metadata.retirementConfirmations
            ⊆ state.retirementCompletedNodes \ retiredCommittedNodes state.log)
    (configured
      : forall nodes,
          content.metadata.configuration = some nodes
          -> Disjoint nodes (removedNodes state.log))
    : EntryOK state.log { term, content } := by
  refine ⟨configured, ?_⟩
  by_cases nonempty : content.metadata.retirementConfirmations.Nonempty
  · exact (confirmations nonempty).trans
      (Finset.sdiff_subset.trans (retirementCompleted_removed ok))
  · rw [Finset.not_nonempty_iff_eq_empty.mp nonempty]
    exact Finset.empty_subset _

private theorem appendEntry_ok (caps : Caps) (self : NodeID) (state : NodeState)
    (content : EntryContent) (ok : LogOK state.log)
    : Keeps (fun after : NodeState => LogOK after.log)
        (Model.Node.appendEntry caps self state content) := by
  unfold Model.Node.appendEntry
  simp only [pure_bind]
  repeat'
    first
    | refine guardBind fun _ => ?_
    | refine Keeps.ite' (fun _ => ?_) fun _ => ?_
    | refine Keeps.seq' fun _ => ?_
    | split
  all_goals
    refine Keeps.pure' (LogOK.append ok (entryOK_of ok ?_ ?_))
  all_goals
    first
    | intro nonempty; first | assumption | contradiction
    | intro nodes configured; simp_all

end Consensus.Proofs.Deadlock.Logs

namespace Consensus.Proofs.Deadlock.Logs

open CCF
open Model.Node
open Direct (Keeps)
section Handlers
variable (caps : Caps) (self : NodeID)

/-- The step only shortens the log, as elections and commits do. -/
private abbrev Shrinks (state after : NodeState) : Prop := after.log <+: state.log

private theorem shrinks_refl (state : NodeState) : Shrinks state state :=
  List.prefix_refl _

private theorem Shrinks.advanced (state : NodeState)
    : Keeps (Shrinks state) (Model.Node.advanceCommit caps state self) := by
  unfold Model.Node.advanceCommit
  refine Keeps.ite' (fun _ => Keeps.pure' (shrinks_refl _)) fun _ => ?_
  have same : Shrinks state (state.recordCommit self (highestCommittableIndex state self)) := by
    simp [Shrinks, Ledger.NodeState.recordCommit_log]
  dsimp only
  exact Keeps.ite'
    (fun _ => Keeps.ite' (fun _ => Keeps.seq' fun _ => Keeps.pure' same)
      fun _ => Keeps.pure' same)
    fun _ => Keeps.pure' same

private theorem Shrinks.becomePrimary (state : NodeState)
    : Keeps (Shrinks state) (Model.Node.becomePrimary caps self state) := by
  unfold Model.Node.becomePrimary
  refine Keeps.bind' (Shrinks.advanced caps self _) fun _ kept =>
    Keeps.seq' fun _ => Keeps.pure' (List.IsPrefix.trans kept ?_)
  simp only [primaryState]
  split
  · exact List.take_prefix _ _
  · exact List.prefix_refl _

private theorem Shrinks.electIfQuorum (state : NodeState)
    : Keeps (Shrinks state) (Model.Node.electIfQuorum caps self state) := by
  unfold Model.Node.electIfQuorum
  exact Keeps.ite' (fun _ => Shrinks.becomePrimary caps self state)
    fun _ => Keeps.pure' (shrinks_refl _)

private theorem Shrinks.becomeCandidate (state : NodeState)
    : Keeps (Shrinks state) (Model.Node.becomeCandidate caps state self) := by
  unfold Model.Node.becomeCandidate
  exact Keeps.bind' (Shrinks.electIfQuorum caps self _) fun _ kept =>
    Keeps.seq' fun _ => Keeps.pure' kept

private theorem Shrinks.becomePreVoteCandidate (state : NodeState)
    : Keeps (Shrinks state) (Model.Node.becomePreVoteCandidate caps state self) := by
  unfold Model.Node.becomePreVoteCandidate
  exact Keeps.ite' (fun _ => Shrinks.becomeCandidate caps self _)
    fun _ => Keeps.seq' fun _ => Keeps.pure' (shrinks_refl _)

private theorem act_ok (state : NodeState) (input : Input) (ok : LogOK state.log)
    : Keeps (fun after : NodeState => LogOK after.log)
        (Model.Node.act caps self state input) := by
  have viaShrinks : forall {m : NodeEffect NodeState}, Keeps (Shrinks state) m
      -> Keeps (fun after : NodeState => LogOK after.log) m :=
    fun kept => kept.mono fun _ shrunk => ok.prefix shrunk
  cases input with
  | append entries =>
      unfold Model.Node.act Model.Node.appendBatch
      refine Keeps.seq' fun _ => ?_
      exact Keeps.bind'
        (Keeps.foldlM' (P := fun current : NodeState => LogOK current.log)
          (fun current entry kept =>
            Keeps.bind' (appendEntry_ok caps self current entry.content kept)
              fun appended next => Keeps.foldlM'
                (fun current (destination, endIndex) kept => by
                  unfold Model.Node.sendEntries
                  exact Keeps.seq' fun _ => Keeps.seq' fun _ => Keeps.pure' kept)
                entry.flushes appended next)
          entries state ok)
        fun current kept => (Shrinks.advanced caps self current).mono fun _ shrunk =>
          kept.prefix shrunk
  | sendEntries destination endIndex =>
      unfold Model.Node.act Model.Node.sendEntries
      exact Keeps.seq' fun _ => Keeps.seq' fun _ => Keeps.pure' ok
  | timeout kind =>
      cases kind with
      | election =>
          unfold Model.Node.act Model.Node.startElection
          exact Keeps.seq' fun _ => viaShrinks (Shrinks.becomePreVoteCandidate caps self state)
      | checkQuorum =>
          unfold Model.Node.act Model.Node.checkQuorum
          exact Keeps.seq' fun _ => Keeps.pure' ok
  | nominateSuccessor =>
      exact (Direct.Keeps.nominateSuccessor caps self state).mono fun _ same => same ▸ ok

/-- Accepting AppendEntries leaves the follower in the request's term. -/
private theorem handleAppendEntriesRequest_term (source : NodeID) (state : NodeState)
    (request : AppendEntriesRequest) (observed : request.term <= state.currentTerm)
    : Keeps
        (fun after : NodeState =>
          after.log = state.log \/ after.currentTerm = request.term)
        (Model.Node.handleAppendEntriesRequest caps self source state request) := by
  unfold Model.Node.handleAppendEntriesRequest
  have stepped : (if request.term = state.currentTerm /\
      (state.role = .candidate \/ state.role = .preVoteCandidate) then
        becomeAwareOfNewTerm state request.term else state).log = state.log
      /\ request.term <= (if request.term = state.currentTerm /\
      (state.role = .candidate \/ state.role = .preVoteCandidate) then
        becomeAwareOfNewTerm state request.term else state).currentTerm := by
    split
    · exact ⟨rfl, by simp [becomeAwareOfNewTerm]⟩
    · exact ⟨rfl, observed⟩
  generalize (if request.term = state.currentTerm /\
      (state.role = .candidate \/ state.role = .preVoteCandidate) then
        becomeAwareOfNewTerm state request.term else state) = current
    at stepped
  obtain ⟨logEq, termLe⟩ := stepped
  refine Keeps.ite' (fun _ => by
    dsimp only
    split <;> exact Keeps.seq' fun _ => Keeps.pure' (Or.inl logEq)) fun accepted => ?_
  have termEq : current.currentTerm = request.term :=
    Nat.le_antisymm (Nat.le_of_not_lt fun lt => accepted (Or.inl lt)) termLe
  dsimp only
  have fromLeader : forall (middle : NodeState), middle.currentTerm = request.term
      -> (handleAppendEntiresFromPrimary self middle request).1.currentTerm = request.term := by
    intro middle middleTerm
    obtain ⟨_, _, _, eq, _⟩ := Ledger.handleAppendEntiresFromPrimary_eq self middle request
    rw [eq]
    exact middleTerm
  refine Keeps.ite' (fun _ => Keeps.pure' (Or.inr termEq)) fun _ => ?_
  split
  · exact Keeps.seq' fun _ => Keeps.pure' (Or.inr (fromLeader _ termEq))
  · exact Keeps.seq' fun _ => Keeps.pure' (Or.inr (fromLeader _ termEq))

private theorem updateTerm_ge (state : NodeState) (term : Nat)
    : term <= (updateTerm state term).currentTerm := by
  unfold updateTerm becomeAwareOfNewTerm
  split
  · exact le_rfl
  · exact Nat.le_of_not_lt ‹_›

/-- Only accepting AppendEntries may produce a log that is not `LogOK`. -/
private theorem step_ok (state : NodeState) (event : Event) (ok : LogOK state.log)
    : Keeps
        (fun after : NodeState =>
          LogOK after.log
          \/ exists source request,
              event = .receive source (.appendEntriesRequest request)
              /\ after.currentTerm = request.term)
        (Model.Node.step caps self state event) := by
  cases event with
  | internal input =>
      exact (act_ok caps self state input ok).mono fun _ kept => Or.inl kept
  | receive source message =>
      unfold Model.Node.step Model.Node.receive
      refine Keeps.ite' (fun _ => Keeps.pure' (Or.inl ok)) fun _ => ?_
      dsimp only
      have observedLog : (observeTerm state message).log = state.log :=
        Concrete.observeTerm_log _ _
      have viaShrinks : forall {m : NodeEffect NodeState},
          Keeps (Shrinks (observeTerm state message)) m
          -> Keeps (fun after : NodeState =>
                LogOK after.log
                \/ exists source' request,
                    Event.receive source message
                      = .receive source' (.appendEntriesRequest request)
                    /\ after.currentTerm = request.term) m :=
        fun kept => kept.mono fun _ shrunk => Or.inl (ok.prefix (observedLog ▸ shrunk))
      cases message with
      | appendEntriesRequest request =>
          have observed : request.term <= (observeTerm state
              (.appendEntriesRequest request)).currentTerm := updateTerm_ge _ _
          refine (handleAppendEntriesRequest_term caps self source _ request observed).mono
            fun _ result => ?_
          rcases result with logEq | termEq
          · exact Or.inl (logEq.trans observedLog ▸ ok)
          · exact Or.inr ⟨source, request, rfl, termEq⟩
      | appendEntriesResponse response =>
          refine viaShrinks ?_
          unfold Model.Node.handleAppendEntriesResponse
          refine Keeps.ite' (fun _ => Keeps.pure' (shrinks_refl _)) fun _ => ?_
          refine Keeps.ite' (fun _ => ?_) fun _ => Keeps.pure' (shrinks_refl _)
          refine Keeps.ite' (fun _ => ?_) fun _ => Keeps.pure' (shrinks_refl _)
          exact Shrinks.advanced caps self _
      | requestVoteRequest request =>
          refine viaShrinks ?_
          unfold Model.Node.handleRequestVoteRequest
          exact Keeps.seq' fun _ => Keeps.pure' (by split <;> exact shrinks_refl _)
      | requestVoteResponse response =>
          refine viaShrinks ?_
          unfold Model.Node.handleRequestVoteResponse
          refine Keeps.ite' (fun _ => ?_) fun _ => Keeps.pure' (shrinks_refl _)
          exact Shrinks.electIfQuorum caps self _
      | requestPreVoteRequest request =>
          refine viaShrinks ?_
          unfold Model.Node.handleRequestPreVoteRequest
          exact Keeps.seq' fun _ => Keeps.pure' (shrinks_refl _)
      | requestPreVoteResponse response =>
          refine viaShrinks ?_
          unfold Model.Node.handleRequestPreVoteResponse
          refine Keeps.ite' (fun _ => ?_) fun _ => Keeps.pure' (shrinks_refl _)
          dsimp only
          refine Keeps.ite' (fun _ => ?_) fun _ => Keeps.pure' (shrinks_refl _)
          exact Shrinks.becomeCandidate caps self _
      | proposeRequestVoteRequest term =>
          refine viaShrinks ?_
          unfold Model.Node.handleProposeRequestVoteRequest
          exact Keeps.ite' (fun _ => Shrinks.becomeCandidate caps self _)
            fun _ => Keeps.pure' (shrinks_refl _)

end Handlers
end Consensus.Proofs.Deadlock.Logs

namespace Consensus.Proofs.Deadlock.Logs

open CCF
open Model.Node
open Safety (History Now Canon CanonNow Exec Everywhere Ctx MessageOK)
variable [Config.InitialConfiguration]

/-- Every log a leader held while leading its term is `LogOK`. -/
private def LeaderLogsOK (history : History) : Prop :=
  forall node state term, CanonNow history node state term -> LogOK state.log

private theorem initial_logs_ok {nodes : List NodeID} {initial : Model.State}
    (initialized
      : (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes).init initial)
    {node : NodeID} {state : NodeState} (member : (node, state) ∈ initial.nodes)
    : LogOK state.log := by
  rw [Safety.initial_state initialized member]
  unfold Safety.initialLocal
  split
  · intro n bound
    simp only [List.length_singleton, Nat.lt_one_iff] at bound
    subst bound
    refine ⟨fun nodes _ => ?_, ?_⟩
    · simp [removedNodes, configurationHistory, configurationMembers]
    · simp [Config.GENESIS, EntryContent.metadata]
  · exact LogOK.nil

end Consensus.Proofs.Deadlock.Logs

namespace Consensus.Proofs.Deadlock.Logs.Ctx

open CCF
open Model.Node
open Safety (History Now Canon CanonNow Exec Everywhere Ctx MessageOK)
variable [Config.InitialConfiguration]
variable {nodes : List NodeID} {after before : Model.State}
  {rest : History} (c : Ctx nodes after before rest)
include c

/-- Every current log is a prefix of a leader log, so is `LogOK`. -/
private theorem pre_ok (ih : Everywhere LeaderLogsOK (before :: rest)) {node : NodeID}
    {state : NodeState} (now : Now (before :: rest) node state)
    : LogOK state.log := by
  rcases Nat.eq_zero_or_pos state.log.length with empty | positive
  · rw [List.length_eq_zero_iff.mp empty]
    exact LogOK.nil
  obtain ⟨log, ⟨earlier, suffix, leader, leaderState, canonNow, rfl⟩, _, eq⟩ :=
    c.inv.anchor node state state.log.length now positive le_rfl
  have nonempty : Not (earlier = []) := by
    rintro rfl
    exact canonNow.1
  have leaderOk := ih earlier suffix nonempty leader leaderState _ canonNow
  rw [List.take_length] at eq
  rw [eq]
  exact leaderOk.take _

private theorem leader_logs (ih : Everywhere LeaderLogsOK (before :: rest))
    : LeaderLogsOK (after :: before :: rest) := by
  intro node state term ⟨now, termEq, role, led⟩
  rcases c.now_after now with ⟨rfl, rfl⟩ | ⟨different, old⟩
  · have preOk := Logs.Ctx.pre_ok c ih c.pre_now
    rcases step_ok (Capabilities.record c.actor) c.actor c.pre c.event preOk _ _ _ c.tr.ran with
      ok | ⟨source, request, received, termEq'⟩
    · exact ok
    · exfalso
      obtain ⟨envelope, ok, sourceEq, targetEq, payload⟩ := c.received_ok received
      simp only [MessageOK, payload] at ok
      obtain ⟨earlier, suffix, sender, ⟨_, senderTerm, _, senderLed⟩, aeok⟩ := ok
      have ledSender := senderLed.mono (suffix.trans c.suffix_tail)
      have ledActor : Safety.Led (after :: before :: rest) c.actor request.term := by
        rw [← termEq', termEq]
        exact led
      have same := c.election_safety _ _ _ ledSender ledActor
      exact aeok.1 (targetEq.trans same.symm)
  · exact ih _ (List.suffix_refl _) (List.cons_ne_nil _ _) node state term
      ⟨old, termEq, role, c.led_other different led⟩

end Consensus.Proofs.Deadlock.Logs.Ctx

namespace Consensus.Proofs.Deadlock.Logs

open CCF
open Model.Node
open Safety (History Now Canon CanonNow Exec Everywhere Ctx MessageOK)
variable [Config.InitialConfiguration]

private theorem leader_logs_of_exec {nodes : List NodeID} {history : History}
    (exec : Exec nodes history)
    : Everywhere LeaderLogsOK history := by
  induction exec with
  | initial initialized =>
      intro earlier suffix nonempty
      rcases List.suffix_cons_iff.mp suffix with rfl | inner
      · intro node state term canonNow
        exact initial_logs_ok initialized canonNow.1
      · exact (nonempty (List.eq_nil_of_suffix_nil inner)).elim
  | step prior stepped ih =>
      obtain ⟨transition⟩ := Safety.LocalTransition.ofStep stepped
      have c : Ctx nodes _ _ _ := ⟨.step prior stepped, transition, Safety.good_of_exec prior⟩
      intro earlier suffix nonempty
      rcases List.suffix_cons_iff.mp suffix with rfl | inner
      · exact Logs.Ctx.leader_logs c ih
      · exact ih earlier inner nonempty

end Consensus.Proofs.Deadlock.Logs

namespace Consensus.Proofs.Deadlock.Configs

open Model.Node

private theorem mem_configurationHistory {log : List Entry}
    {configuration : Configuration}
    : configuration ∈ configurationHistory log
      <-> exists n,
      exists bound : n < log.length,
        configuration.index = n + 1
        /\ log[n].content.metadata.configuration = some configuration.nodes := by
  unfold configurationHistory
  rw [List.mem_filterMap]
  constructor
  · rintro ⟨⟨entry, index⟩, member, eq⟩
    obtain ⟨low, high, entryEq⟩ := List.mem_zipIdx member
    obtain ⟨nodes, configured, rfl⟩ := Option.map_eq_some_iff.mp eq
    refine ⟨index - 1, by omega, by simp; omega, ?_⟩
    rw [← entryEq]
    exact configured
  · rintro ⟨n, bound, indexEq, configured⟩
    have inZip : n < (log.zipIdx 1).length := by rw [List.length_zipIdx]; exact bound
    refine ⟨(log[n], n + 1), ?_, ?_⟩
    · have := List.getElem_mem inZip
      rwa [List.getElem_zipIdx, Nat.add_comm 1 n] at this
    · obtain ⟨index, nodes⟩ := configuration
      simp only at indexEq configured
      simp [configured, indexEq]

private theorem index_bounds {log : List Entry} {configuration : Configuration}
    (member : configuration ∈ configurationHistory log)
    : 1 <= configuration.index /\ configuration.index <= log.length := by
  obtain ⟨n, bound, indexEq, _⟩ := mem_configurationHistory.mp member
  omega

private theorem pairwise_zipIdx {α : Type} (xs : List α) (k : Nat)
    : (xs.zipIdx k).Pairwise fun first second => first.2 < second.2 := by
  induction xs generalizing k with
  | nil => simp
  | cons head tail ih =>
      rw [List.zipIdx_cons, List.pairwise_cons]
      refine ⟨fun ⟨_, index⟩ member => ?_, ih (k + 1)⟩
      have := (List.mem_zipIdx member).1
      simp only
      omega

/-- Configuration indices strictly increase along the history. -/
private theorem history_sorted (log : List Entry)
    : (configurationHistory log).Pairwise
        fun first second => first.index < second.index := by
  unfold configurationHistory
  refine (pairwise_zipIdx log 1).filterMap _ ?_
  rintro ⟨_, i⟩ ⟨_, j⟩ lt first firstEq second secondEq
  obtain ⟨_, _, rfl⟩ := Option.map_eq_some_iff.mp firstEq
  obtain ⟨_, _, rfl⟩ := Option.map_eq_some_iff.mp secondEq
  exact lt

/-- A configuration of a prefix is a configuration of the whole log. -/
private theorem history_of_prefix {small large : List Entry} (sub : small <+: large)
    {configuration : Configuration} (member : configuration ∈ configurationHistory small)
    : configuration ∈ configurationHistory large := by
  obtain ⟨n, bound, indexEq, configured⟩ := mem_configurationHistory.mp member
  have inLarge : n < large.length := Nat.lt_of_lt_of_le bound sub.length_le
  refine mem_configurationHistory.mpr ⟨n, inLarge, indexEq, ?_⟩
  rw [← sub.getElem bound]
  exact configured

/-- A configuration of the whole log within a prefix belongs to the prefix. -/
private theorem history_to_prefix {small large : List Entry} (sub : small <+: large)
    {configuration : Configuration} (member : configuration ∈ configurationHistory large)
    (within : configuration.index <= small.length)
    : configuration ∈ configurationHistory small := by
  obtain ⟨n, bound, indexEq, configured⟩ := mem_configurationHistory.mp member
  have inSmall : n < small.length := by omega
  refine mem_configurationHistory.mpr ⟨n, inSmall, indexEq, ?_⟩
  rw [sub.getElem inSmall]
  exact configured

/-- Every element of a strictly sorted list is at most its last element. -/
private theorem le_getLast {history : List Configuration}
    (sorted : history.Pairwise fun first second => first.index < second.index)
    (nonempty : history ≠ []) {configuration : Configuration}
    (member : configuration ∈ history)
    : configuration.index <= (history.getLast nonempty).index := by
  have split := List.dropLast_append_getLast nonempty
  rw [← split] at sorted member
  rcases List.mem_append.mp member with early | last
  · exact Nat.le_of_lt ((List.pairwise_append.mp sorted).2.2 _ early _ (List.mem_singleton_self _))
  · rw [List.mem_singleton.mp last]

private theorem latest_eq {history : List Configuration} (nonempty : history ≠ [])
    : latestConfigurationMembers history = (history.getLast nonempty).nodes := by
  simp [latestConfigurationMembers, List.getLast?_eq_some_getLast nonempty]

private theorem mem_configurationMembers_foldl {node : NodeID}
    (history : List Configuration) (init : Finset NodeID)
    : node ∈ history.foldl (fun nodes configuration => nodes ∪ configuration.nodes) init
      <-> node ∈ init
          \/ exists configuration,
              configuration ∈ history /\ node ∈ configuration.nodes := by
  induction history generalizing init with
  | nil => simp
  | cons head tail ih =>
      simp only [List.foldl_cons, ih, Finset.mem_union, List.mem_cons]
      constructor
      · rintro ((old | new) | ⟨configuration, member, present⟩)
        · exact Or.inl old
        · exact Or.inr ⟨head, Or.inl rfl, new⟩
        · exact Or.inr ⟨configuration, Or.inr member, present⟩
      · rintro (old | ⟨configuration, rfl | member, present⟩)
        · exact Or.inl (Or.inl old)
        · exact Or.inl (Or.inr present)
        · exact Or.inr ⟨configuration, member, present⟩

private theorem mem_configurationMembers {history : List Configuration}
    {configuration : Configuration} (member : configuration ∈ history) {node : NodeID}
    (present : node ∈ configuration.nodes)
    : node ∈ configurationMembers history := by
  unfold configurationMembers
  exact (mem_configurationMembers_foldl history ∅).mpr
    (Or.inr ⟨configuration, member, present⟩)

/-- A configuration at or after the last one with index at most `bound` is active. -/
private theorem mem_drop_of_latest {history : List Configuration}
    (sorted : history.Pairwise fun first second => first.index < second.index)
    {configuration : Configuration} (member : configuration ∈ history) {bound : Nat}
    (latest
      : forall other,
          other ∈ history -> other.index <= bound -> other.index <= configuration.index)
    : configuration
      ∈ history.drop
          ((history.filter fun other => decide (other.index <= bound)).length - 1) := by
  induction history with
  | nil => simp at member
  | cons head tail ih =>
      rw [List.pairwise_cons] at sorted
      rw [List.filter_cons]
      by_cases headIn : head.index <= bound
      · simp only [headIn, decide_true, ite_true, List.length_cons, Nat.add_sub_cancel]
        cases count : (tail.filter fun other => decide (other.index <= bound)).length with
        | zero => simpa using member
        | succ count =>
            obtain ⟨other, otherMem⟩ :=
              List.exists_mem_of_length_pos (by omega : 0 < (tail.filter fun other =>
                decide (other.index <= bound)).length)
            have ⟨otherTail, otherIn⟩ := List.mem_filter.mp otherMem
            have notHead : configuration ≠ head := by
              rintro rfl
              have := latest other (List.mem_cons_of_mem _ otherTail) (by simpa using otherIn)
              have := sorted.1 other otherTail
              omega
            have inTail : configuration ∈ tail := by
              rcases List.mem_cons.mp member with rfl | inner
              · exact (notHead rfl).elim
              · exact inner
            have rest := ih sorted.2 inTail fun other otherMem =>
              latest other (List.mem_cons_of_mem _ otherMem)
            rw [count] at rest
            simpa [List.drop_succ_cons] using rest
      · have none : (tail.filter fun other => decide (other.index <= bound)) = [] := by
          refine List.filter_eq_nil_iff.mpr fun other otherTail => ?_
          have := sorted.1 other otherTail
          simp only [decide_eq_true_eq]
          omega
        simp only [headIn, decide_false, Bool.false_eq_true, ite_false, none,
          List.length_nil, Nat.zero_sub, List.drop_zero]
        exact member

end Consensus.Proofs.Deadlock.Configs

namespace Consensus.Proofs.Deadlock.Witness

set_option linter.unusedSectionVars false
open CCF CCF.MultiNodeTransitionSystem
open Model.Node
open Safety (History Now Seen Canon CanonNow Exec Everywhere Committed CommitStep Inv)
open Configs Logs
variable [Config.InitialConfiguration]

/-- Every state of an execution has the declared node identities. -/
private theorem exec_keys {nodes : List NodeID} {history : History}
    (exec : Exec nodes history) {state : Model.State} (member : state ∈ history)
    : state.nodes.map Prod.fst = nodes := by
  induction exec generalizing state with
  | initial initialized =>
      rw [List.mem_singleton.mp member]
      exact initialized.2.1
  | step prior stepped ih =>
      rcases List.mem_cons.mp member with rfl | older
      · rename_i before _ action
        have keys := ih List.mem_cons_self
        cases action with
        | «local» actor input =>
            obtain ⟨_, _, _, _, _, rfl⟩ := Concrete.step_local stepped
            simpa [Concrete.replaceNode_keys] using keys
        | deliver envelope =>
            obtain ⟨_, _, _, _, _, _, rfl⟩ := Concrete.step_deliver stepped
            simpa [Concrete.replaceNode_keys] using keys
      · exact ih older

/-- Bound on every log length in a history. -/
private def logBound (history : History) : Nat :=
  (history.flatMap fun state => state.nodes.map fun entry => entry.2.log.length).sum

private theorem committed_length_le {history : History} {term : Nat} {part : List Entry}
    (committed : Committed history term part)
    : part.length <= logBound history := by
  obtain ⟨current, rest, leader, state, _, index, suffix, ⟨⟨now, _⟩, _⟩, rfl, _⟩ :=
    committed.shape
  refine (List.length_take_le' _ _).trans (List.le_sum_of_mem ?_)
  exact List.mem_flatMap.mpr ⟨current, suffix.subset List.mem_cons_self,
    List.mem_map.mpr ⟨(leader, state), now, rfl⟩⟩

/-- Some committed part contains every other committed part. -/
private theorem longest_committed {history : History} (inv : Inv history)
    (monos : Everywhere Safety.CanonMono history) {term : Nat} {part : List Entry}
    (committed : Committed history term part)
    : exists term' longest,
        Committed history term' longest
        /\ part.length <= longest.length
        /\ forall term'' other, Committed history term'' other -> other <+: longest := by
  classical
  let holds := fun n => exists term' other, Committed history term' other /\ other.length = n
  have bound := committed_length_le committed
  obtain ⟨term', longest, longestCommitted, lengthEq⟩ :=
    Nat.findGreatest_spec (P := holds) bound ⟨term, part, committed, rfl⟩
  refine ⟨term', longest, longestCommitted, ?_, fun term'' other otherCommitted => ?_⟩
  · rw [lengthEq]
    exact Nat.le_findGreatest bound ⟨term, part, committed, rfl⟩
  · rcases Safety.committed_comparable inv.completeness monos otherCommitted
        longestCommitted with sub | sub
    · exact sub
    · have le : other.length <= longest.length := by
        rw [lengthEq]
        exact Nat.le_findGreatest (committed_length_le otherCommitted)
          ⟨term'', other, otherCommitted, rfl⟩
      rw [sub.eq_of_length (Nat.le_antisymm sub.length_le le)]

/-- The latest configuration of a log prefix, if it is the latest one at or below `bound`. -/
private theorem active_of_latest {log part : List Entry} (sub : part <+: log)
    (nonempty : configurationHistory part ≠ []) {bound : Nat}
    (within : bound <= part.length)
    : (configurationHistory part).getLast nonempty ∈ activeConfigurations log bound := by
  unfold activeConfigurations
  dsimp only
  refine mem_drop_of_latest (history_sorted log)
    (history_of_prefix sub (List.getLast_mem nonempty)) fun other otherMem otherLe => ?_
  exact le_getLast (history_sorted part) nonempty
    (history_to_prefix sub otherMem (otherLe.trans within))

end Consensus.Proofs.Deadlock.Witness

namespace Consensus.Proofs.Deadlock.Witness

set_option linter.unusedSectionVars false
open CCF CCF.MultiNodeTransitionSystem
open Model.Node
open Safety (History Now Seen Canon CanonNow Exec Everywhere Committed CommitStep Inv)
open Configs Logs
variable [Config.InitialConfiguration]

/--
Once some node has committed, the longest committed prefix has a latest
configuration, and an acknowledging member of it holds that prefix: that member
is primary or may campaign.
-/
private theorem witness {nodes : List NodeID} {current : Model.State} {rest : History}
    (exec : Exec nodes (current :: rest))
    (bootstrapped
      : exists earlier node local_,
          earlier ∈ current :: rest
          /\ (node, local_) ∈ earlier.nodes
          /\ 0 < local_.commitIndex)
    : exists node local_,
        (node, local_) ∈ current.nodes
        /\ (local_.role = .primary \/ canStartElection local_ node) := by
  have good := Safety.good_of_exec exec
  have inv : Inv (current :: rest) := good _ (List.suffix_refl _) (List.cons_ne_nil _ _)
  have monos := good.everywhere Inv.canon_mono
  -- Some committed part is nonempty.
  obtain ⟨earlier, node₀, local₀, earlierMem, member₀, positive⟩ := bootstrapped
  obtain ⟨front, back, split⟩ := List.append_of_mem earlierMem
  have suffix₀ : earlier :: back <:+ current :: rest := ⟨front, split.symm⟩
  have inv₀ : Inv (earlier :: back) := good _ suffix₀ (List.cons_ne_nil _ _)
  rcases inv₀.commit_backed node₀ local₀ member₀ with zero | ⟨term₀, part₀, committed₀, _, within₀⟩
  · omega
  have frontier₀ : local₀.commitIndex <= local₀.log.length :=
    Safety.Seen.commit_le (exec.suffix suffix₀ (List.cons_ne_nil _ _))
      (Safety.Now.seen member₀)
  have partPos : 0 < part₀.length := by
    have := within₀.length_le
    rw [List.length_take, Nat.min_eq_left frontier₀] at this
    omega
  obtain ⟨term, part, committed, longer, longest⟩ :=
    longest_committed inv monos (committed₀.mono suffix₀)
  -- The commit step behind the longest committed part.
  obtain ⟨c₁, r₁, leader, leaderState, base, idx, suffix₁, step, partEq, _⟩ := committed.shape
  obtain ⟨canonNow, baseLe, idxLe, signature, _, voters, quorum, acks⟩ := step
  have lenEq : part.length = idx := by rw [partEq, List.length_take, Nat.min_eq_left idxLe]
  have leaderOk : LogOK leaderState.log :=
    leader_logs_of_exec exec _ suffix₁ (List.cons_ne_nil _ _) leader leaderState term canonNow
  have partOk : LogOK part := partEq ▸ leaderOk.take idx
  have partPrefix : part <+: leaderState.log := partEq ▸ List.take_prefix _ _
  have partSignature : isSignatureAt part idx = true := by
    rw [partEq]
    exact Ledger.isSignatureAt_take_of_le le_rfl signature
  -- The part's latest configuration is among those whose quorum acknowledged it.
  obtain ⟨some, someMem⟩ := List.exists_mem_of_ne_nil _ quorum.1
  have someActive := (List.mem_filter.mp someMem).1
  have someLe : some.index <= idx := by simpa using (List.mem_filter.mp someMem).2
  have someHistory : some ∈ configurationHistory leaderState.log := by
    unfold activeConfigurations at someActive
    exact List.mem_of_mem_drop someActive
  have historyNonempty : configurationHistory part ≠ [] :=
    List.ne_nil_of_mem (history_to_prefix partPrefix someHistory (lenEq ▸ someLe))
  have latestLe : ((configurationHistory part).getLast historyNonempty).index <= idx :=
    lenEq ▸ (index_bounds (List.getLast_mem historyNonempty)).2
  have latestFiltered : (configurationHistory part).getLast historyNonempty
      ∈ (activeConfigurations leaderState.log base).filter
          fun configuration => configuration.index <= idx :=
    List.mem_filter.mpr ⟨active_of_latest partPrefix historyNonempty (lenEq ▸ baseLe),
      by simpa using latestLe⟩
  have majority := List.all_eq_true.mp quorum.2 _ latestFiltered
  simp only [decide_eq_true_eq, hasConfigurationMajority] at majority
  obtain ⟨voter, voterMem⟩ : (voters ∩ ((configurationHistory part).getLast
      historyNonempty).nodes).Nonempty :=
    Finset.card_pos.mp (by omega)
  obtain ⟨inVoters, inLatest⟩ := Finset.mem_inter.mp voterMem
  obtain ⟨acker, seen, ackerTerm, ackerLog⟩ := acks voter inVoters
  rw [← partEq] at ackerLog
  -- The acknowledging voter is a declared node.
  have seenNow := seen.mono suffix₁
  have ⟨state', stateMem, voterIn⟩ := seenNow
  have voterKey : voter ∈ current.nodes.map Prod.fst := by
    rw [exec_keys exec List.mem_cons_self, ← exec_keys exec stateMem]
    exact List.mem_map.mpr ⟨_, voterIn, rfl⟩
  obtain ⟨⟨key, voterState⟩, voterMember, keyEq⟩ := List.mem_map.mp voterKey
  simp only at keyEq
  subst keyEq
  -- The voter still holds the committed part.
  have ackerTake : acker.log.take idx = part := by
    rw [← lenEq]
    exact (List.prefix_iff_eq_take.mp ackerLog).symm
  have ackerSignature : isSignatureAt acker.log idx = true :=
    Ledger.isSignatureAt_of_prefix ackerLog partSignature
  have partInVoter : part <+: voterState.log := by
    rcases inv.persist key voterState acker idx voterMember seenNow ackerSignature with
      kept | ⟨later, log, lt, _, canon, missing⟩
    · rwa [ackerTake] at kept
    · exfalso
      have ackerTermAt : termAt acker.log idx = term := by
        rw [← Safety.termAt_take (le_refl idx), ackerTake, ← lenEq]
        exact committed.signature.2.1
      rw [ackerTake] at missing
      rw [ackerTermAt] at lt
      exact missing (Safety.committed_in_canon inv.completeness monos committed canon lt)
  -- Its committed log lies within the longest committed part.
  have committedInPart : voterState.committedLog <+: part := by
    rcases inv.commit_backed key voterState voterMember with
      zero | ⟨_, other, otherCommitted, _, within⟩
    · simp [NodeState.committedLog, zero]
    · exact within.trans (longest _ _ otherCommitted)
  have frontier : voterState.commitIndex <= voterState.log.length :=
    Safety.Seen.commit_le exec (Safety.Now.seen voterMember)
  have commitLe : voterState.commitIndex <= part.length := by
    have := committedInPart.length_le
    rwa [NodeState.committedLog, List.length_take, Nat.min_eq_left frontier] at this
  -- It is not retired, so it has a role.
  have loc := Direct.NodeInvariant.reachable Local.loc_invariant exec.reachable key voterState
    voterMember
  have notRemoved : key ∉ removedNodes part := by
    simp only [removedNodes, latest_eq historyNonempty, Finset.mem_sdiff, not_and, not_not]
    exact fun _ => inLatest
  have latchNone : voterState.retiredCommittedIndex = none := by
    cases latch : voterState.retiredCommittedIndex with
    | none => rfl
    | some _ =>
        exfalso
        have confirmed := retiredCommittedNodes_mono committedInPart (loc.1 (by simp [latch]))
        obtain ⟨entry, entryMem, inConfirmations⟩ := mem_retiredCommittedNodes.mp confirmed
        obtain ⟨n, bound, rfl⟩ := List.getElem_of_mem entryMem
        exact notRemoved
          (removedNodes_prefix partOk (List.take_prefix _ _)
            ((partOk n bound).2 inConfirmations))
  have two : 2 <= voterState.currentTerm := by
    have := inv.term_mono key voterState acker voterMember seenNow
    rw [ackerTerm] at this
    exact committed.signature.2.2.trans this
  have active : Not (voterState.role = .none) := by
    intro none
    rcases loc.2 none with some | young
    · simp [latchNone] at some
    · omega
  refine ⟨key, voterState, voterMember, ?_⟩
  by_cases primary : voterState.role = .primary
  · exact Or.inl primary
  right
  refine ⟨?_, Or.inl ?_, fun retired => ?_⟩
  · cases role : voterState.role <;> simp_all
  · refine mem_configurationMembers (configuration :=
      (configurationHistory part).getLast historyNonempty) ?_ inLatest
    unfold NodeState.signedActiveConfigurations NodeState.activeConfigurations
    refine List.mem_filter.mpr ⟨active_of_latest partInVoter historyNonempty commitLe, ?_⟩
    have signed : idx <= maxCommittableIndex voterState.log :=
      Ledger.signatureIndex_le_maxCommittableIndex
        (Ledger.isSignatureAt_of_prefix partInVoter partSignature)
    simpa using latestLe.trans signed
  · have := Local.latch_of_retired retired
    simp [latchNone] at this

end Consensus.Proofs.Deadlock.Witness

namespace Consensus.Proofs.Deadlock

open CCF
open Model.Node

public theorem deadlock_free_after_bootstrap (config : Finset NodeID)
    (nodes : List NodeID)
    : ({
            Model.transitionSystem config nodes with
              init :=
                fun state =>
                  (Model.transitionSystem config nodes).Reachable state
                  /\ exists (node : NodeID) (local_ : NodeState),
                      (node, local_) ∈ state.nodes /\ 0 < local_.commitIndex
          }
        : TransitionSystem).DeadlockFree := by
  let _ : Config.InitialConfiguration := ⟨config⟩
  intro state reachable
  have traced : exists history,
      Safety.Exec nodes (state :: history)
      /\ exists earlier node local_,
          earlier ∈ state :: history
          /\ (node, local_) ∈ earlier.nodes
          /\ 0 < local_.commitIndex := by
    induction reachable with
    | initial initialized =>
        obtain ⟨original, node, local_, member, positive⟩ := initialized
        obtain ⟨history, exec⟩ := Safety.exec_of_reachable original
        exact ⟨history, exec, _, node, local_, List.mem_cons_self, member, positive⟩
    | step _ stepped ih =>
        obtain ⟨history, exec, earlier, node, local_, earlierMem, member, positive⟩ := ih
        exact ⟨_, .step exec stepped, earlier, node, local_,
          List.mem_cons_of_mem _ earlierMem, member, positive⟩
  obtain ⟨history, exec, bootstrapped⟩ := traced
  obtain ⟨node, local_, member, acts⟩ := Witness.witness exec bootstrapped
  exact enabled_of_member (config := config) (nodes := nodes)
    (exec.keys List.mem_cons_self) member acts

end Consensus.Proofs.Deadlock
