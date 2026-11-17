module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.TraceValidation.Proofs.Obligation
public import Consensus.TraceValidation.Proofs.Monad

@[expose] public section

/-!
# Lemmas for the vote obligations (not reviewed)

Shared by `RequestVote` and `RequestPreVote`:

* `Det`: a handler that deterministically maps the declared state and appends sends, with
  combinators and the `vote_det` tactic; `det_recvRequestVote` computes `recv_request_vote`
  as the functions `rvVars` and `rvOut`.
* Links between `inv` and the clean model: `lastCommittable_eq` and `getTerm_eq` relate
  M_tv's `lastCommittable` and `getTerm` to clean `maxCommittableIndex` and `termAt`;
  `votedFor_link` relates `voted_for` to the clean `votedFor` through the name table.
* `inv_get` and the `inv_conj` tactic: one named conjunct of `inv`.
* The clean receive steps `clean_preVote` and `clean_vote`, and `agrees` after them.
-/

namespace Consensus.TraceValidation.Proofs.Vote

open Consensus.Model.Node
open Consensus.TraceValidation.Exec
open CCF.Sections (LocalRun)

/-- `x` deterministically maps the declared state by `f` and appends `g` to the outbox. -/
def Det {α : Type} (env : Env) (x : M α) (f : State -> State) (g : State -> Outbox)
    : Prop :=
  Spec env x fun v o _ v' o' => v' = f v /\ o' = o ++ g v

namespace Det
variable {env : Env}

theorem ofKeeps {α : Type} {x : M α} (h : Spec.Keeps env x)
    : Det env x id (fun _ => []) :=
  Spec.weaken h fun _ _ _ _ _ ⟨a, b⟩ => ⟨a, by simp [b]⟩

theorem bind {α β : Type} {x : M α} {k : α -> M β} {f f' : State -> State}
    {g g' : State -> Outbox} (hx : Det env x f g) (hk : forall a, Det env (k a) f' g')
    : Det env (x >>= k) (fun v => f' (f v)) (fun v => g v ++ g' (f v)) :=
  Spec.weaken (Spec.bind hx hk)
    fun _ _ _ _ _ ⟨_, _, _, ⟨h1, h2⟩, h3, h4⟩ => by
      subst h1 h2; exact ⟨h3, by simp [h4]⟩

theorem getV_bind {β : Type} {k : State -> M β} {f : State -> State -> State}
    {g : State -> State -> Outbox} (hk : forall s, Det env (k s) (f s) (g s))
    : Det env (Exec.getV >>= k) (fun v => f v v) (fun v => g v v) :=
  Spec.weaken (Spec.bind Spec.getV hk)
    fun _ _ _ _ _ ⟨_, _, _, ⟨h0, h1, h2⟩, h3, h4⟩ => by
      subst h0 h1 h2; exact ⟨h3, h4⟩

theorem ite {α : Type} {b : Prop} [Decidable b] {x y : M α} {f f' : State -> State}
    {g g' : State -> Outbox} (hx : Det env x f g) (hy : Det env y f' g')
    : Det env (if b then x else y) (fun v => if b then f v else f' v)
        (fun v => if b then g v else g' v) :=
  Spec.weaken (Spec.ite hx hy)
    fun _ _ _ _ _ ⟨p, q⟩ => by
      by_cases hb : b
      · simpa [hb] using p hb
      · simpa [hb] using q hb

theorem pure {α : Type} (a : α) : Det env (Pure.pure a : M α) id (fun _ => []) :=
  ofKeeps (Spec.Keeps.pure a)

theorem setV (f : State -> State) : Det env (Exec.setV f) f (fun _ => []) :=
  Spec.weaken (Spec.setV f) fun _ _ _ _ _ ⟨a, b⟩ => ⟨a, by simp [b]⟩

theorem send (dst : NodeId) (m : Message)
    : Det env (Exec.send dst m) id
        (fun v => [CCF.Envelope.mk (env.names.id v.nodeId) (env.names.id dst) m]) :=
  Spec.weaken (Spec.send dst m) fun _ _ _ _ _ ⟨a, b⟩ => ⟨a, b⟩

theorem trace (fn : String) : Det env (Exec.trace fn) id (fun _ => []) :=
  ofKeeps (Spec.trace fn)

theorem emit (k : String) (j : Lean.Json) : Det env (Exec.emit k j) id (fun _ => []) :=
  ofKeeps (Spec.emit k j)

theorem emitStr (k s : String) : Det env (Exec.emitStr k s) id (fun _ => []) :=
  ofKeeps (Spec.emitStr k s)

theorem congr {α : Type} {x : M α} {f f' : State -> State} {g g' : State -> Outbox}
    (h : Det env x f g) (hf : forall v, f v = f' v) (hg : forall v, g v = g' v)
    : Det env x f' g' := by
  have e1 : f = f' := funext hf
  have e2 : g = g' := funext hg
  subst e1 e2; exact h

theorem run {f : State -> State} {g : State -> Outbox} {x : M Unit} (h : Det env x f g)
    {vars : State} {queue : List Action} {final : Bool} {c : Ctx}
    (ran : Exec.run env vars queue final x = .ok c)
    : c.vars = f vars /\ c.outbox = g vars := by
  have := Spec.run h ran
  simpa using this

end Det

/-- Decompose a handler built from `getV`, `setV`, `send` and trace points into `Det`. -/
macro "vote_det" : tactic =>
  `(tactic| repeat' (first
    | with_reducible exact Consensus.TraceValidation.Proofs.Vote.Det.pure _
    | with_reducible exact Consensus.TraceValidation.Proofs.Vote.Det.setV _
    | with_reducible exact Consensus.TraceValidation.Proofs.Vote.Det.send _ _
    | with_reducible exact Consensus.TraceValidation.Proofs.Vote.Det.trace _
    | with_reducible exact Consensus.TraceValidation.Proofs.Vote.Det.emit _ _
    | with_reducible exact Consensus.TraceValidation.Proofs.Vote.Det.emitStr _ _
    | with_reducible apply Consensus.TraceValidation.Proofs.Vote.Det.getV_bind
    | with_reducible apply Consensus.TraceValidation.Proofs.Vote.Det.bind
    | with_reducible apply Consensus.TraceValidation.Proofs.Vote.Det.ite
    | with_reducible intro))

theorem det_traceRecv (env : Env) (fn : String) (from_ : NodeId) (m : Message)
    : Det env (Exec.traceRecv fn from_ m) id (fun _ => []) := by
  unfold Exec.traceRecv
  apply Det.congr
  · vote_det
  all_goals intro v; simp

def bant (t : Nat) (v : State) : State :=
  {
    v with
      votedFor := if v.currentView != t then none else v.votedFor
      currentView := t
      votesForMe := v.configurations.map fun c => (c.idx, [], State.quorum c.nodes.length)
      leaderId := none
      leadership := .follower
      isNewFollower := true
  }

theorem det_becomeAware (env : Env) (t : Nat)
    : Det env (Exec.becomeAwareOfNewTerm t) (bant t) (fun _ => []) := by
  unfold Exec.becomeAwareOfNewTerm Exec.resetVotesForMe Exec.becomeFollower
  apply Det.congr
  · vote_det
  all_goals intro v; simp [bant]

def rvGrant (pre : Bool) (from_ : NodeId) (r : RequestVoteRequest) (v : State) : Bool :=
  !(!pre && v.leaderId.isSome)
  && !(!pre && v.votedFor.any (· != from_))
  && (decide (r.lastCommittableTerm > v.getTerm v.lastCommittable)
      || r.lastCommittableTerm == v.getTerm v.lastCommittable
          && decide (r.lastCommittableIndex >= v.lastCommittable))

def rvMid (r : RequestVoteRequest) (v : State) : State :=
  if v.currentView < r.term then bant r.term v else v

def rvVars (pre : Bool) (from_ : NodeId) (r : RequestVoteRequest) (v : State) : State :=
  if v.currentView > r.term then
    v
  else if rvGrant pre from_ r (rvMid r v) && !pre then
    { rvMid r v with leaderId := none, votedFor := some from_ }
  else
    rvMid r v

def rvResp (pre : Bool) (t : Nat) (g : Bool) : Message :=
  if pre then
    .requestPreVoteResponse { term := t, voteGranted := g }
  else
    .requestVoteResponse { term := t, voteGranted := g }

def rvOut (env : Env) (pre : Bool) (from_ : NodeId) (r : RequestVoteRequest) (v : State)
    : Outbox :=
  [CCF.Envelope.mk (env.names.id v.nodeId) (env.names.id from_)
    (if v.currentView > r.term then
        rvResp pre v.currentView false
      else
        rvResp pre (rvMid r v).currentView (rvGrant pre from_ r (rvMid r v)))]

@[simp]
theorem bant_lastCommittable (t : Nat) (v : State)
    : (bant t v).lastCommittable = v.lastCommittable :=
  rfl

@[simp] theorem bant_getTerm (t : Nat) (v : State) : (bant t v).getTerm = v.getTerm := rfl

theorem det_recvRequestVote (env : Env) (from_ : NodeId) (pre : Bool)
    (r : RequestVoteRequest)
    : Det env (Exec.recvRequestVote from_ pre r) (rvVars pre from_ r)
        (rvOut env pre from_ r) := by
  unfold Exec.recvRequestVote
  unfold Exec.traceRecv Exec.becomeAwareOfNewTerm Exec.resetVotesForMe Exec.becomeFollower
  dsimp only
  apply Det.congr
  · vote_det
  all_goals
    intro v
    simp only [rvVars, rvOut, rvMid, rvGrant, rvResp]
    by_cases h1 : v.currentView > r.term
    · simp [h1]
    · by_cases h2 : v.currentView < r.term <;> cases pre <;> simp [h1, h2, bant, State.lastCommittable, State.getTerm] <;> (repeat' split) <;> simp_all <;> (cases hl : v.leaderId <;> simp_all)

theorem eligiblePeers_congr {a b : NodeState} (hl : a.log = b.log)
    (hc : a.commitIndex = b.commitIndex) (self : NodeID)
    : eligiblePeers a self = eligiblePeers b self := by
  unfold eligiblePeers NodeState.activeMembers NodeState.retirementCompletedNodes
    NodeState.activeConfigurations NodeState.committedLog
  rw [hl, hc]

theorem foldMax_ge_start (p : Nat -> Bool) (l : List Nat) (b : Nat)
    : b <= l.foldl (fun best i => if p i then max best i else best) b := by
  induction l generalizing b with
  | nil => exact Nat.le_refl _
  | cons x xs ih =>
      simp only [List.foldl_cons]
      refine Nat.le_trans ?_ (ih _)
      split <;> omega

theorem foldMax_ge_mem (p : Nat -> Bool) (l : List Nat) (b i : Nat) (hi : i ∈ l)
    (hp : p i = true)
    : i <= l.foldl (fun best i => if p i then max best i else best) b := by
  induction l generalizing b with
  | nil => simp at hi
  | cons x xs ih =>
      simp only [List.foldl_cons]
      rcases List.mem_cons.mp hi with rfl | hi
      · refine Nat.le_trans ?_ (foldMax_ge_start p xs _)
        simp only [hp, ite_true]; omega
      · exact ih _ hi

theorem foldMax_cases (p : Nat -> Bool) (l : List Nat) (b : Nat)
    : l.foldl (fun best i => if p i then max best i else best) b = b
      ∨ p (l.foldl (fun best i => if p i then max best i else best) b) = true := by
  induction l generalizing b with
  | nil => exact Or.inl rfl
  | cons x xs ih =>
      simp only [List.foldl_cons]
      rcases ih (if p x then max b x else b) with h | h
      · rw [h]
        by_cases hx : p x
        · simp only [hx, ite_true]
          rcases Nat.le_total b x with hb | hb
          · rw [Nat.max_eq_right hb]; exact Or.inr hx
          · rw [Nat.max_eq_left hb]; exact Or.inl rfl
        · simp [hx]
      · exact Or.inr h

theorem isSignatureAt_le_length {log : List Model.Node.Entry} {i : Nat}
    (h : isSignatureAt log i = true)
    : i <= log.length := by
  unfold isSignatureAt entryAt? at h
  split at h
  · rename_i e he
    split at he
    · simp at he
    · have := (List.getElem?_eq_some_iff.mp he).1
      omega
  · simp at h

theorem isSignatureAt_zero (log : List Model.Node.Entry)
    : isSignatureAt log 0 = false := by
  simp [isSignatureAt, entryAt?]

theorem eq_maxCommittableIndex {log : List Model.Node.Entry} {m : Nat}
    (h0 : m = 0 ∨ isSignatureAt log m = true)
    (hall : forall i, isSignatureAt log i = true -> i <= m)
    : maxCommittableIndex log = m := by
  unfold maxCommittableIndex
  apply Nat.le_antisymm
  · rcases foldMax_cases (isSignatureAt log) (List.range (log.length + 1)) 0 with h | h
    · rw [h]; exact Nat.zero_le _
    · exact hall _ h
  · rcases h0 with h | h
    · rw [h]; exact Nat.zero_le _
    · exact foldMax_ge_mem _ _ _ _
        (List.mem_range.mpr (Nat.lt_succ_of_le (isSignatureAt_le_length h))) h

theorem le_of_getLast?
    : forall {l : List Nat} {x : Nat},
        l.Pairwise (· < ·) -> l.getLast? = some x -> forall y, y ∈ l -> y <= x
  | [], _, _, h, _, _ => by simp at h
  | [a], _, _, h, _, hy => by simp at h hy; omega
  | a :: b :: l, x, hp, h, y, hy => by
      have hp' := List.pairwise_cons.mp hp
      have h' : (b :: l).getLast? = some x := by simpa using h
      have ih := le_of_getLast? hp'.2 h'
      rcases List.mem_cons.mp hy with rfl | hy
      · exact Nat.le_of_lt (Nat.lt_of_lt_of_le (hp'.1 b (by simp)) (ih b (by simp)))
      · exact ih y hy

theorem isSignatureAt_abs {names : Names} {d : State} (h : d.ledger.size = d.lastIdx)
    (i : Nat)
    : isSignatureAt (abs names d).log i = (i != 0 && d.ledger[i - 1]?.any (·.sig)) := by
  have htake : d.ledger.toList.take d.lastIdx = d.ledger.toList := by
    rw [← h, ← Array.length_toList, List.take_length]
  simp only [abs, htake, isSignatureAt, entryAt?]
  by_cases hi : i = 0
  · simp [hi]
  · simp only [hi, ite_false, List.getElem?_map, Array.getElem?_toList]
    cases d.ledger[i - 1]? with
    | none => simp
    | some e => cases hs : e.sig <;> simp [absEntry, hs, EntryContent.isSignature, hi]

theorem termAt_abs {names : Names} {d : State} (h : d.ledger.size = d.lastIdx) (i : Nat)
    : termAt (abs names d).log i
      = if i = 0 then 0 else (d.ledger[i - 1]?.map (·.term)).getD 0 := by
  have htake : d.ledger.toList.take d.lastIdx = d.ledger.toList := by
    rw [← h, ← Array.length_toList, List.take_length]
  simp only [abs, htake, termAt, entryAt?]
  by_cases hi : i = 0
  · simp [hi]
  · simp only [hi, ite_false, List.getElem?_map, Array.getElem?_toList]
    cases d.ledger[i - 1]? <;> simp [absEntry]

theorem inv_get {names : Names} {d : State} (h : inv names d = true) (n : String)
    : ((invChecks names d).lookup n).getD true = true := by
  unfold inv at h
  generalize invChecks names d = l at h ⊢
  induction l with
  | nil => rfl
  | cons p ps ih =>
      obtain ⟨k, b⟩ := p
      simp only [List.all_cons, Bool.and_eq_true] at h
      simp only [List.lookup]
      split
      · simpa using h.1
      · exact ih h.2

/-- The conjunct of `inv` named `n`, from `h : inv names d = true`. -/
macro "inv_conj " h:term:max n:str : tactic =>
  `(tactic| (
    have hc := Consensus.TraceValidation.Proofs.Vote.inv_get $h $n
    simp only [invChecks, List.lookup, String.reduceBEq, Option.getD_some] at hc
    first | exact hc | simpa using hc))

theorem inv_parts {names : Names} {d : State} (h : inv names d = true)
    : d.ledger.size = d.lastIdx
      /\ d.commitIdx <= d.lastIdx
      /\ d.committable = signaturesIn d d.commitIdx d.lastIdx
      /\ (d.commitIdx = 0 \/ d.ledger[d.commitIdx - 1]?.any (·.sig) = true)
      /\ (forall i,
            1 <= i -> i <= d.lastIdx -> d.ledger[i - 1]?.map (·.term) = some (d.viewAt i))
      /\ d.views.size <= d.currentView
      /\ d.views.all (0 < ·) = true := by
  refine ⟨
    by inv_conj h "ledger_size",
    by inv_conj h "commit_le_last",
    by inv_conj h "committable",
    by inv_conj h "commit_at_signature",
    ?_,
    by inv_conj h "views_bounded",
    by inv_conj h "views_positive"
  ⟩
  intro i hi1 hi2
  have h5 : (List.range' 1 d.lastIdx).all
      (fun i => d.ledger[i - 1]?.map (·.term) == some (d.viewAt i)) = true := by
    inv_conj h "terms_are_views"
  have := List.all_eq_true.mp h5 i (List.mem_range'.mpr ⟨i - 1, by omega, by omega⟩)
  simpa using this

theorem lastCommittable_eq_of {names : Names} {d : State} (h1 : d.ledger.size = d.lastIdx)
    (h3 : d.committable = signaturesIn d d.commitIdx d.lastIdx)
    (h4 : d.commitIdx = 0 \/ d.ledger[d.commitIdx - 1]?.any (·.sig) = true)
    : d.lastCommittable = maxCommittableIndex (abs names d).log := by
  have hsig := isSignatureAt_abs (names := names) h1
  have hmem : forall x, x ∈ d.committable ↔ (d.commitIdx < x /\ x <= d.lastIdx
      /\ d.ledger[x - 1]?.any (·.sig) = true) := by
    intro x
    rw [h3]
    simp only [signaturesIn, List.mem_filter, List.mem_range']
    constructor
    · rintro ⟨⟨k, hk, rfl⟩, hs⟩; exact ⟨by omega, by omega, hs⟩
    · rintro ⟨a, b, c⟩; exact ⟨⟨x - (d.commitIdx + 1), by omega, by omega⟩, c⟩
  have hsorted : d.committable.Pairwise (· < ·) := by
    rw [h3]; exact (List.pairwise_lt_range' ..).filter _
  have hbound : forall i, d.ledger[i - 1]?.any (·.sig) = true -> i != 0 -> i <= d.lastIdx := by
    intro i hs hi
    cases he : d.ledger[i - 1]? with
    | none => simp [he] at hs
    | some e =>
        have := (Array.getElem?_eq_some_iff.mp he).1
        simp at hi; omega
  symm
  unfold State.lastCommittable
  cases hl : d.committable.getLast? with
  | none =>
      have hnil : d.committable = [] := List.getLast?_eq_none_iff.mp hl
      simp only [Option.getD_none]
      apply eq_maxCommittableIndex
      · by_cases hc : d.commitIdx = 0
        · exact Or.inl hc
        · right; rw [hsig]
          have h4 := h4.resolve_left hc
          simp only [h4, Bool.and_true]; simpa using hc
      · intro i hi
        rw [hsig] at hi
        simp only [Bool.and_eq_true] at hi
        refine Nat.le_of_not_lt fun hlt => ?_
        have := (hmem i).mpr ⟨hlt, hbound i hi.2 hi.1, hi.2⟩
        simp [hnil] at this
  | some x =>
      simp only [Option.getD_some]
      have hx := (hmem x).mp (List.mem_of_getLast? hl)
      apply eq_maxCommittableIndex
      · right; rw [hsig]; simp only [hx.2.2, Bool.and_true]; simp; omega
      · intro i hi
        rw [hsig] at hi
        simp only [Bool.and_eq_true] at hi
        by_cases hlt : d.commitIdx < i
        · exact le_of_getLast? hsorted hl i ((hmem i).mpr ⟨hlt, hbound i hi.2 hi.1, hi.2⟩)
        · omega

theorem lastCommittable_eq {names : Names} {d : State} (h : inv names d = true)
    : d.lastCommittable = maxCommittableIndex (abs names d).log := by
  obtain ⟨h1, -, h3, h4, -⟩ := inv_parts h
  exact lastCommittable_eq_of h1 h3 h4

theorem viewAt_zero {d : State} (h : d.views.all (0 < ·) = true) : d.viewAt 0 = 0 := by
  simp only [State.viewAt, List.length_eq_zero_iff, List.filter_eq_nil_iff]
  intro x hx
  have := (Array.all_eq_true_iff_forall_mem.mp h) x (by simpa using hx)
  simp at this ⊢; omega

theorem getTerm_eq {names : Names} {d : State} (h : inv names d = true) (i : Nat)
    : d.getTerm i = termAt (abs names d).log i := by
  obtain ⟨h1, -, -, -, h5, -, h7⟩ := inv_parts h
  rw [termAt_abs h1]
  unfold State.getTerm
  by_cases hi : i = 0
  · subst hi; simp [viewAt_zero h7]
  · by_cases hl : i > d.lastIdx
    · have : d.ledger[i - 1]? = none := by simp; omega
      simp [hl, hi, this]
    · simp only [hl, hi, ite_false]
      rw [h5 i (by omega) (by omega)]; rfl

/-- `voteLogUpToDate`, as the clean step computes it. -/
def cleanLogOk (s : NodeState) (r : RequestVoteRequest) : Bool :=
  decide (maxCommittableTerm s.log < r.lastCommittableTerm)
  || decide (maxCommittableTerm s.log = r.lastCommittableTerm)
      && decide (maxCommittableIndex s.log <= r.lastCommittableIndex)

theorem decide_preVote (s : NodeState) (r : RequestVoteRequest) (t : Nat)
    : decide (t = s.currentTerm ∧ voteLogUpToDate s r)
      = (decide (t = s.currentTerm) && cleanLogOk s r) := by
  rw [Bool.eq_iff_iff, decide_eq_true_iff]
  simp [cleanLogOk, voteLogUpToDate, CCF.TxID.le]

theorem clean_preVote (node source : NodeID) (clean : NodeState) (r : RequestVoteRequest)
    : (Consensus.Model.Node.step (CCF.Capabilities.record node) node clean
        (.receive source (.requestPreVoteRequest r))).run
        {}
      = some
          (
            updateTerm clean r.term,
            {
              outgoing :=
                [⟨
                  node,
                  source,
                  .requestPreVoteResponse
                    {
                      term := (updateTerm clean r.term).currentTerm,
                      voteGranted :=
                        decide (r.term = (updateTerm clean r.term).currentTerm)
                        && cleanLogOk (updateTerm clean r.term) r
                    }
                ⟩]
            }
          ) := by
  simp [Consensus.Model.Node.step, Model.Node.receive, handleRequestPreVoteRequest,
    CCF.Capabilities.record, observeTerm, Message.term]
  exact decide_preVote _ _ _

theorem agrees_bant {names : Names} {c : NodeState} {d : State} (t : Nat)
    (h : agrees names c d = true)
    : agrees names (Model.Node.becomeAwareOfNewTerm c t) (bant t d) = true := by
  simp only [agrees, Bool.and_eq_true, beq_iff_eq] at h ⊢
  obtain ⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨h1, h2⟩, h3⟩, h4⟩, h5⟩, h6⟩, h7⟩, h8⟩, h9⟩, h10⟩, h11⟩ := h
  simp only [abs, bant, Model.Node.becomeAwareOfNewTerm, trackedPeers, absRole] at *
  rw [h2]
  by_cases ht : d.currentView = t <;> simp [ht, h3, h4, h7, h11] <;> decide

theorem logOk_eq {names : Names} {c : NodeState} {d : State} (h : inv names d = true)
    (hlog : c.log = (abs names d).log) (r : RequestVoteRequest)
    : (decide (r.lastCommittableTerm > d.getTerm d.lastCommittable)
        || r.lastCommittableTerm == d.getTerm d.lastCommittable
            && decide (r.lastCommittableIndex >= d.lastCommittable))
      = cleanLogOk c r := by
  rw [lastCommittable_eq h, getTerm_eq h, ← hlog]
  simp only [cleanLogOk, maxCommittableTerm]
  by_cases a : termAt c.log (maxCommittableIndex c.log) < r.lastCommittableTerm <;>
  by_cases b : termAt c.log (maxCommittableIndex c.log) = r.lastCommittableTerm <;>
  by_cases e : maxCommittableIndex c.log <= r.lastCommittableIndex <;>
  simp [a, b, e] <;> omega

theorem inv_named {names : Names} {d : State} (h : inv names d = true)
    : d.votedFor.all (fun x => names.name (names.id x) == x) = true
      /\ (d.leadership ≠ .leader ∨ d.leaderId = some d.nodeId) := by
  have h7 : (d.leadership != .leader || d.leaderId == some d.nodeId) = true := by
    inv_conj h "leader_knows_itself"
  refine ⟨by inv_conj h "voted_for_named", ?_⟩
  by_cases hl : d.leadership = .leader
  · right; simpa [hl] using h7
  · exact Or.inl hl

theorem rvVars_nodeId (pre : Bool) (from_ : NodeId) (r : RequestVoteRequest) (v : State)
    : (rvVars pre from_ r v).nodeId = v.nodeId := by
  have hm : (rvMid r v).nodeId = v.nodeId := by unfold rvMid; split <;> rfl
  unfold rvVars
  split
  · rfl
  · split
    · exact hm
    · exact hm

theorem updateTerm_of_lt {c : NodeState} {t : Nat} (h : c.currentTerm < t)
    : updateTerm c t = Model.Node.becomeAwareOfNewTerm c t := by
  simp [updateTerm, h]

theorem updateTerm_of_ge {c : NodeState} {t : Nat} (h : ¬ c.currentTerm < t)
    : updateTerm c t = c := by
  simp [updateTerm, h]

theorem agrees_term_log {names : Names} {c : NodeState} {d : State}
    (h : agrees names c d = true)
    : c.currentTerm = d.currentView /\ c.log = (abs names d).log := by
  simp only [agrees, Bool.and_eq_true, beq_iff_eq] at h
  obtain ⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨-, h2⟩, h3⟩, -⟩, -⟩, -⟩, -⟩, -⟩, -⟩, -⟩, -⟩ := h
  exact ⟨h2, h3⟩

theorem msgInv_source {names : Names} {e : CCF.Envelope NodeID Message}
    (h : msgInv names e = true)
    : names.id (names.name e.source) = e.source := by
  simp only [msgInv, Bool.and_eq_true, beq_iff_eq] at h
  exact h.1.1.1.1

theorem msgInv_reply {names : Names} {node source : NodeID} {m m' : Message}
    (hn : names.id (names.name node) = node) (h : msgInv names ⟨source, node, m⟩ = true)
    (hm' : forall r, m' ≠ .appendEntriesRequest r)
    : msgInv names ⟨node, source, m'⟩ = true := by
  simp only [msgInv, Bool.and_eq_true, beq_iff_eq, bne_iff_ne, ne_eq] at h ⊢
  refine ⟨⟨⟨⟨hn, fun e => h.1.1.1.2 e.symm⟩, ?_⟩, ?_⟩, ?_⟩ <;> cases m' <;> simp_all

theorem agrees_vote_parts {names : Names} {c : NodeState} {d : State}
    (h : agrees names c d = true)
    : c.votedFor = d.votedFor.map names.id /\ c.primaryKnown = d.leaderId.isSome := by
  simp only [agrees, Bool.and_eq_true, beq_iff_eq] at h
  obtain ⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨-, -⟩, -⟩, -⟩, -⟩, -⟩, h7⟩, h8⟩, -⟩, -⟩, -⟩ := h
  exact ⟨h7, h8⟩

def cleanGrant (s : NodeState) (r : RequestVoteRequest) (source : NodeID) : Bool :=
  decide (r.term = s.currentTerm)
  && cleanLogOk s r
  && !s.primaryKnown
  && decide (s.votedFor = none ∨ s.votedFor = some source)

theorem decide_vote (s : NodeState) (r : RequestVoteRequest) (source : NodeID)
    : decide
        (r.term = s.currentTerm
          ∧ voteLogUpToDate s r
          ∧ (!s.primaryKnown) = true
          ∧ (s.votedFor = none ∨ s.votedFor = some source))
      = cleanGrant s r source := by
  rw [Bool.eq_iff_iff, decide_eq_true_iff]
  simp [cleanGrant, cleanLogOk, voteLogUpToDate, CCF.TxID.le, and_assoc]

theorem clean_vote (node source : NodeID) (clean : NodeState) (r : RequestVoteRequest)
    : (Consensus.Model.Node.step (CCF.Capabilities.record node) node clean
        (.receive source (.requestVoteRequest r))).run
        {}
      = some
          (
            if cleanGrant (updateTerm clean r.term) r source then
              { updateTerm clean r.term with votedFor := some source }
            else
              updateTerm clean r.term,
            {
              outgoing :=
                [⟨
                  node,
                  source,
                  .requestVoteResponse
                    {
                      term := (updateTerm clean r.term).currentTerm,
                      voteGranted := cleanGrant (updateTerm clean r.term) r source
                    }
                ⟩]
            }
          ) := by
  simp [Consensus.Model.Node.step, Model.Node.receive, handleRequestVoteRequest,
    CCF.Capabilities.record, observeTerm, Message.term]
  rw [← decide_vote]
  simp

theorem votedFor_link {names : Names} {x : Option NodeId} {src : NodeID}
    (hx : x.all (fun y => names.name (names.id y) == y) = true)
    (hs : names.id (names.name src) = src)
    : (!x.any (· != names.name src))
      = decide (x.map names.id = none ∨ x.map names.id = some src) := by
  cases x with
  | none => simp
  | some y =>
      simp only [Option.all_some, beq_iff_eq] at hx
      simp only [Option.any_some, Option.map_some, reduceCtorEq, Option.some.injEq, false_or]
      by_cases hy : y = names.name src
      · subst hy; simp [hs]
      · have : names.id y ≠ src := fun e => hy (by rw [← hx, e])
        simp [hy, this]

theorem agrees_vote {names : Names} {c : NodeState} {d : State} {src : NodeID}
    (h : agrees names c d = true) (hl : d.leaderId = none)
    (hs : names.id (names.name src) = src)
    : agrees names { c with votedFor := some src }
        { d with leaderId := none, votedFor := some (names.name src) }
      = true := by
  have ha : abs names { d with leaderId := none, votedFor := some (names.name src) }
      = { abs names d with votedFor := some src } := by
    simp [abs, hl, hs]
  have ht : trackedPeers names { d with leaderId := none, votedFor := some (names.name src) }
      = trackedPeers names d := rfl
  simp only [agrees, Bool.and_eq_true, beq_iff_eq] at h ⊢
  rw [ha, ht]
  obtain ⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨h1, h2⟩, h3⟩, h4⟩, h5⟩, h6⟩, -⟩, h8⟩, h9⟩, h10⟩, h11⟩ := h
  exact ⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨h1, h2⟩, h3⟩, h4⟩, h5⟩, h6⟩, rfl⟩, h8⟩, h9⟩, h10⟩, h11⟩

theorem rvMid_frame {names : Names} (r : RequestVoteRequest) (d : State)
    : (rvMid r d).lastCommittable = d.lastCommittable
      /\ (rvMid r d).getTerm = d.getTerm
      /\ (abs names (rvMid r d)).log = (abs names d).log
      /\ ((rvMid r d).votedFor = none \/ (rvMid r d).votedFor = d.votedFor) := by
  unfold rvMid
  split
  · refine ⟨rfl, rfl, rfl, ?_⟩
    simp only [bant]; split <;> simp
  · exact ⟨rfl, rfl, rfl, Or.inr rfl⟩

theorem rvGrant_eq {names : Names} {s : NodeState} {d : State} {r : RequestVoteRequest}
    {source : NodeID} (hd : inv names d = true) (ha : agrees names s (rvMid r d) = true)
    (ht : (rvMid r d).currentView = r.term) (hs : names.id (names.name source) = source)
    : rvGrant false (names.name source) r (rvMid r d) = cleanGrant s r source := by
  obtain ⟨hterm, hlog⟩ := agrees_term_log ha
  obtain ⟨hvf, hpk⟩ := agrees_vote_parts ha
  obtain ⟨hlc, hgt, hal, hvd⟩ := rvMid_frame (names := names) r d
  rw [hal] at hlog
  have hok := logOk_eq hd hlog r
  have hnamed : (rvMid r d).votedFor.all (fun x => names.name (names.id x) == x) = true := by
    rcases hvd with h | h
    · rw [h]; rfl
    · rw [h]; exact (inv_named hd).1
  have hl := votedFor_link hnamed hs
  simp only [rvGrant, cleanGrant, Bool.not_false, Bool.true_and, hlc, hgt]
  rw [hok, hvf, ← hl, hpk, hterm, ht]
  simp only [decide_true, Bool.true_and]
  generalize cleanLogOk s r = a
  generalize (rvMid r d).leaderId.isSome = b
  generalize (!(rvMid r d).votedFor.any (· != names.name source)) = e
  cases a <;> cases b <;> cases e <;> rfl

theorem rvMid_agrees {names : Names} {clean : NodeState} {d : State}
    {r : RequestVoteRequest} (h : agrees names clean d = true)
    (hgt : ¬ d.currentView > r.term)
    : agrees names (updateTerm clean r.term) (rvMid r d) = true
      /\ (rvMid r d).currentView = r.term := by
  obtain ⟨hterm, -⟩ := agrees_term_log h
  by_cases hlt : d.currentView < r.term
  · have hu : updateTerm clean r.term = Model.Node.becomeAwareOfNewTerm clean r.term := updateTerm_of_lt (by omega)
    simp only [rvMid, hlt, ite_true, hu]
    exact ⟨agrees_bant _ h, rfl⟩
  · have hu : updateTerm clean r.term = clean := updateTerm_of_ge (by omega)
    simp only [rvMid, hlt, ite_false, hu]
    exact ⟨h, by omega⟩

/-- `UnnamedUnmatched` reads only the role, the log and the match indexes of a primary. -/
theorem unmatched_frame {node : NodeID} {c c' : NodeState} (h : UnnamedUnmatched node c)
    (keeps
      : c'.role = .primary
        -> c.role = .primary /\ c'.log = c.log /\ c'.matchIndex = c.matchIndex)
    : UnnamedUnmatched node c' := by
  intro primary n ne notNamed
  obtain ⟨p, hl, hm⟩ := keeps primary
  rw [hm]
  exact h p n ne (hl ▸ notNamed)

theorem unmatched_updateTerm {node : NodeID} {c : NodeState} (t : Nat)
    (h : UnnamedUnmatched node c)
    : UnnamedUnmatched node (updateTerm c t) := by
  refine unmatched_frame h fun p => ?_
  by_cases lt : c.currentTerm < t
  · simp [updateTerm, lt, Model.Node.becomeAwareOfNewTerm] at p
  · simp only [updateTerm, lt, ite_false] at p ⊢
    exact ⟨p, trivial, trivial⟩

end Consensus.TraceValidation.Proofs.Vote
