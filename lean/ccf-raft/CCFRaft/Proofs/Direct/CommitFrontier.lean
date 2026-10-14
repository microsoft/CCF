module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import CCFRaft.Proofs.Direct.Effects
public import CCFRaft.Proofs.Direct.Framework
public import CCFRaft.Properties
public import CCFRaft.Proofs.Ledger

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# Commit frontiers

Every node's commit index lies within its log and, when positive, points to a
signature. The property is local: each local step preserves it, whatever the
message it handles.
-/

namespace CCFRaft.Proofs.Direct

open CCFRaft.Proofs.Config

open CCF
open Model.Node
open Ledger (
  isSignatureAt_of_prefix isSignatureAt_take_of_le
    signatureIndex_le_maxCommittableIndex maxCommittableIndexUpTo_le_length
    maxCommittableIndexUpToPositiveIsSignature
  )

variable {Node TxId : Type} [DecidableEq Node] [DecidableEq TxId] [InitialConfig Node]
  [LinearOrder Node] [Inhabited TxId]

/-- The commit index lies within the log and, when positive, is a signature. -/
def CommitFrontier (state : NodeState Node TxId) : Prop :=
  state.commitIndex <= state.log.length
  /\ (0 < state.commitIndex -> isSignatureAt state.log state.commitIndex = true)

theorem CommitFrontier.of_log {state after : NodeState Node TxId}
    (frontier : CommitFrontier state) (logEq : after.log = state.log)
    (commitEq : after.commitIndex = state.commitIndex)
    : CommitFrontier after := by
  unfold CommitFrontier at *
  rw [logEq, commitEq]
  exact frontier

theorem CommitFrontier.extend {state : NodeState Node TxId}
    (frontier : CommitFrontier state) {log : List (Entry Node TxId)}
    (extends_ : state.log <+: log)
    : CommitFrontier { state with log } := by
  refine ⟨frontier.1.trans extends_.length_le, fun positive => ?_⟩
  exact isSignatureAt_of_prefix extends_ (frontier.2 positive)

theorem CommitFrontier.keep {state : NodeState Node TxId}
    (frontier : CommitFrontier state) {count : Nat} (within : state.commitIndex <= count)
    {suffix : List (Entry Node TxId)}
    : CommitFrontier { state with log := state.log.take count ++ suffix } := by
  refine ⟨?_, fun positive => ?_⟩
  · simp only [List.length_append, List.length_take]
    have := frontier.1
    omega
  · exact isSignatureAt_of_prefix (List.prefix_append _ _)
      (isSignatureAt_take_of_le within (frontier.2 positive))

/-- A new commit frontier chosen from the latest covered signature. -/
theorem CommitFrontier.advance {state : NodeState Node TxId}
    {log : List (Entry Node TxId)} {bound : Nat}
    (extends_ : CommitFrontier { state with log })
    : CommitFrontier
        {
          state with
            log, commitIndex := max state.commitIndex (maxCommittableIndexUpTo log bound)
        } := by
  refine ⟨max_le extends_.1 (maxCommittableIndexUpTo_le_length log bound), fun positive => ?_⟩
  simp only at positive ⊢
  rcases Nat.le_total state.commitIndex (maxCommittableIndexUpTo log bound) with le | le
  · rw [max_eq_right le] at positive ⊢
    exact maxCommittableIndexUpToPositiveIsSignature positive
  · rw [max_eq_left le] at positive ⊢
    exact extends_.2 positive

theorem foldl_select_max (P : Nat -> Prop) [DecidablePred P] (values : List Nat)
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
            simp [chosen, max_eq_right le]
          · left
            simp [chosen, max_eq_left le]
        · simp [chosen]
      · exact Or.inr holds

theorem foldl_select_max_pos (P : Nat -> Prop) [DecidablePred P] (values : List Nat)
    (positive
      : 0 < values.foldl (fun best index => if P index then max best index else best) 0)
    : P
        (values.foldl (fun best index => if P index then max best index else best)
          0) := by
  rcases foldl_select_max P values 0 with zero | holds
  · rw [zero] at positive
    omega
  · exact holds

theorem highestCommittableIndex_signature (state : NodeState Node TxId) (self : Node)
    (positive : 0 < highestCommittableIndex (inferInstance) state self)
    : isSignatureAt state.log (highestCommittableIndex (inferInstance) state self)
      = true := by
  unfold highestCommittableIndex at positive ⊢
  exact (foldl_select_max_pos _ _ positive).2.1

theorem signature_le_length {log : List (Entry Node TxId)} {index : Nat}
    (signature : isSignatureAt log index = true)
    : index <= log.length := by
  obtain ⟨entry, found, _⟩ := Ledger.isSignatureAtTrue signature
  exact Ledger.entryAtSomeIndexBound found

theorem CommitFrontier.leaderAppendState {state : NodeState Node TxId}
    (frontier : CommitFrontier state) (content : EntryContent Node TxId)
    : CommitFrontier
        { state with log := state.log ++ [{ term := state.currentTerm, content }] } :=
  frontier.extend (List.prefix_append _ _)

section AppendEntries

variable {self : Node} {state : NodeState Node TxId}
  {request : AppendEntriesRequest Node TxId}

theorem CommitFrontier.fromLeader (frontier : CommitFrontier state)
    : CommitFrontier
        (handleAppendEntiresFromLeader (inferInstance) self state request).1 := by
  have advanced := CommitFrontier.advance
    (bound := min request.leaderCommit (request.prevLogIndex + request.entries.length))
    (frontier.extend (List.prefix_append state.log
      (request.entries.drop (state.log.length - request.prevLogIndex))))
  unfold handleAppendEntiresFromLeader
  exact advanced.of_log rfl rfl

theorem CommitFrontier.handleAppendEntriesRequest (frontier : CommitFrontier state)
    (caps : Caps Node TxId) (source : Node)
    : Keeps CommitFrontier
        (Model.Node.handleAppendEntriesRequest (inferInstance) caps self source state
          request) := by
  unfold Model.Node.handleAppendEntriesRequest
  have stepped : CommitFrontier (if request.term = state.currentTerm /\
      (state.role = .candidate \/ state.role = .preVoteCandidate) then
        { state with role := .follower, isNewFollower := true } else state) := by
    split
    · exact frontier.of_log rfl rfl
    · exact frontier
  generalize (if request.term = state.currentTerm /\
      (state.role = .candidate \/ state.role = .preVoteCandidate) then
        { state with role := .follower, isNewFollower := true } else state) = current
    at stepped
  refine Keeps.ite' (fun _ => by
    dsimp only
    split <;> exact Keeps.seq' fun _ => Keeps.pure' stepped) fun _ => ?_
  dsimp only
  refine Keeps.ite' (fun _ => Keeps.pure' (stepped.of_log rfl rfl)) fun notBefore => ?_
  have within : current.commitIndex <= request.prevLogIndex := by
    simp only [not_or] at notBefore
    omega
  have prepared : CommitFrontier
      (if hasTermConflict { current with leaderKnown := true } request then
        {
          current with
            leaderKnown := true
            log := current.log.take request.prevLogIndex, isNewFollower := false
        }
      else { current with leaderKnown := true }) := by
    split
    · exact (stepped.keep within (suffix := [])).of_log (by simp) rfl
    · exact stepped.of_log rfl rfl
  generalize (if hasTermConflict { current with leaderKnown := true } request then
        {
          current with
            leaderKnown := true
            log := current.log.take request.prevLogIndex, isNewFollower := false
        }
      else { current with leaderKnown := true }) = prepared' at prepared
  exact Keeps.seq' fun _ => Keeps.pure' prepared.fromLeader

end AppendEntries

theorem CommitFrontier.advanced {state : NodeState Node TxId} (self : Node)
    (frontier : CommitFrontier state) (caps : Caps Node TxId)
    : Keeps CommitFrontier
        (Model.Node.advanceCommit (inferInstance) caps state self) := by
  unfold Model.Node.advanceCommit
  refine Keeps.ite' (fun _ => Keeps.pure' frontier) fun ahead => ?_
  have signature := highestCommittableIndex_signature state self (by omega)
  have advanced : CommitFrontier
      (state.commitThrough self (highestCommittableIndex (inferInstance) state self)) :=
    ⟨by simpa [NodeState.commitThrough] using signature_le_length signature,
      fun _ => by simpa [NodeState.commitThrough] using signature⟩
  dsimp only
  refine Keeps.ite'
    (fun _ =>
      Keeps.ite' (fun _ => Keeps.seq' fun _ => Keeps.pure' (advanced.of_log rfl rfl))
        fun _ => Keeps.pure' (advanced.of_log rfl rfl))
    fun _ => Keeps.pure' advanced

theorem CommitFrontier.withSent {state : NodeState Node TxId}
    (frontier : CommitFrontier state) {sentIndex : Node -> Nat}
    : CommitFrontier { state with sentIndex } :=
  frontier.of_log rfl rfl

theorem CommitFrontier.truncateToSignature {state : NodeState Node TxId}
    (frontier : CommitFrontier state)
    : state.commitIndex <= maxCommittableIndex state.log := by
  by_cases zero : state.commitIndex = 0
  · omega
  · exact signatureIndex_le_maxCommittableIndex (frontier.2 (Nat.pos_of_ne_zero zero))

/-- The log a new leader keeps: its signed prefix, or everything at startup. -/
theorem CommitFrontier.promotedLog {state : NodeState Node TxId}
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
      (by unfold lastCommittableIndex; omega) (suffix := [])
    exact kept.of_log (by simp) rfl
  · exact frontier.of_log rfl rfl

section Handlers

variable (caps : Caps Node TxId) (self : Node)

theorem CommitFrontier.appendEntry {state : NodeState Node TxId}
    (frontier : CommitFrontier state) (content : EntryContent Node TxId)
    : Keeps CommitFrontier
        (Model.Node.appendEntry (inferInstance) caps self state content) := by
  unfold Model.Node.appendEntry
  cases content with
  | signature =>
      exact Keeps.seq' fun _ => Keeps.pure' (frontier.leaderAppendState _)
  | transaction txId effects =>
      dsimp only
      refine Keeps.bind'
        (Q := fun (pair : NodeState Node TxId × List (TransactionEffect Node)) =>
          CommitFrontier pair.1) ?_
        fun pair kept => Keeps.pure' (kept.leaderAppendState _)
      refine Keeps.foldlM'
        (P := fun (pair : NodeState Node TxId × List (TransactionEffect Node)) =>
          CommitFrontier pair.1) ?_ effects (state, []) frontier
      intro ⟨current, done⟩ effect kept
      refine Keeps.bind' (Q := CommitFrontier) ?_ fun _ next => Keeps.pure' next
      unfold Model.Node.applyTransactionEffect
      cases effect with
      | reconfiguration nodes =>
          exact Keeps.seq' fun _ => Keeps.seq' fun _ => Keeps.pure' kept.withSent
      | retiredCommitted nodes =>
          exact Keeps.seq' fun _ => Keeps.pure' kept

theorem CommitFrontier.becomeLeader {state : NodeState Node TxId}
    (frontier : CommitFrontier state)
    : Keeps CommitFrontier (Model.Node.becomeLeader (inferInstance) caps self state) := by
  unfold Model.Node.becomeLeader
  refine Keeps.bind' (CommitFrontier.advanced self ?_ caps) fun _ kept =>
      Keeps.seq' fun _ => Keeps.pure' kept
  unfold Model.Node.leaderState
  exact frontier.promotedLog.of_log rfl rfl

theorem CommitFrontier.electIfQuorum {state : NodeState Node TxId}
    (frontier : CommitFrontier state)
    : Keeps CommitFrontier
        (Model.Node.electIfQuorum (inferInstance) caps self state) := by
  unfold Model.Node.electIfQuorum
  exact Keeps.ite' (fun _ => frontier.becomeLeader caps self) fun _ => Keeps.pure' frontier

theorem CommitFrontier.becomeCandidate {state : NodeState Node TxId}
    (frontier : CommitFrontier state)
    : Keeps CommitFrontier
        (Model.Node.becomeCandidate (inferInstance) caps state self) := by
  unfold Model.Node.becomeCandidate
  refine Keeps.bind' (CommitFrontier.electIfQuorum caps self ?_) fun _ kept =>
    Keeps.seq' fun _ => Keeps.pure' kept
  exact frontier.of_log rfl rfl

theorem CommitFrontier.becomePreVoteCandidate {state : NodeState Node TxId}
    (frontier : CommitFrontier state)
    : Keeps CommitFrontier
        (Model.Node.becomePreVoteCandidate (inferInstance) caps state self) := by
  unfold Model.Node.becomePreVoteCandidate
  refine Keeps.ite' (fun _ => CommitFrontier.becomeCandidate caps self ?_)
    fun _ => Keeps.seq' fun _ => Keeps.pure' ?_ <;> exact frontier.of_log rfl rfl

theorem CommitFrontier.act {state : NodeState Node TxId}
    (frontier : CommitFrontier state) (input : Input Node TxId)
    : Keeps CommitFrontier (Model.Node.act (inferInstance) caps self state input) := by
  cases input with
  | append entries =>
      unfold Model.Node.act Model.Node.appendBatch
      exact Keeps.seq' fun _ => Keeps.bind'
        (Keeps.foldlM' (fun current content kept => kept.appendEntry caps self content)
          entries state frontier)
        fun _ kept => kept.advanced self caps
  | sendEntries destination endIndex =>
      unfold Model.Node.act Model.Node.sendEntries
      exact Keeps.seq' fun _ => Keeps.seq' fun _ => Keeps.pure' frontier.withSent
  | timeout kind =>
      cases kind with
      | election =>
          unfold Model.Node.act Model.Node.startElection
          exact Keeps.seq' fun _ => Keeps.ite'
            (fun _ => frontier.becomePreVoteCandidate caps self)
            fun _ => frontier.becomeCandidate caps self
      | checkQuorum =>
          unfold Model.Node.act Model.Node.checkQuorum
          exact Keeps.seq' fun _ => Keeps.pure' (frontier.of_log rfl rfl)
  | nominateSuccessor =>
      unfold Model.Node.act
      exact Keeps.seq' fun _ => Keeps.seq' fun _ =>
        Keeps.pure' (frontier.of_log rfl rfl)

theorem CommitFrontier.receive {state : NodeState Node TxId}
    (frontier : CommitFrontier state) (source : Node) (message : Message Node TxId)
    : Keeps CommitFrontier
        (Model.Node.receive (inferInstance) caps self source state message) := by
  have observed : CommitFrontier (observeTerm state message) :=
    frontier.of_log (Concrete.observeTerm_log _ _) (Concrete.observeTerm_commitIndex _ _)
  unfold Model.Node.receive
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
  | requestPreVote request =>
      unfold Model.Node.handleRequestPreVote
      exact Keeps.seq' fun _ => Keeps.pure' observed
  | requestPreVoteResponse response =>
      unfold Model.Node.handleRequestPreVoteResponse
      refine Keeps.ite' (fun _ => ?_) fun _ => Keeps.pure' observed
      dsimp only
      exact Keeps.ite' (fun _ => CommitFrontier.becomeCandidate caps self (observed.of_log rfl rfl))
        fun _ => Keeps.pure' (observed.of_log rfl rfl)
  | proposeVoteRequest term =>
      unfold Model.Node.handleProposeVoteRequest
      exact Keeps.ite' (fun _ => CommitFrontier.becomeCandidate caps self observed)
        fun _ => Keeps.pure' observed

end Handlers

theorem commitFrontier_invariant
    : Direct.NodeInvariant (Node := Node) (TxId := TxId)
        fun _ state => CommitFrontier state := by
  refine ⟨
    fun node => ⟨Nat.zero_le _, fun positive => by simp [initialNodeState] at positive⟩,
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

theorem committed_frontier_is_signature : Properties.CommittedFrontierIsSignature := by
  intro Node TxId _ _ _ _ config nodes trace state node nodeState ⟨valid, member, listed, positive⟩
  let _ : Model.Node.InitialConfig Node := config
  exact (commitFrontier_invariant.reachable (valid.reachable member) node nodeState listed).2
    positive

end CCFRaft.Proofs.Direct
