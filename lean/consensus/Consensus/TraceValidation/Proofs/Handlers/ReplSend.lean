module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.TraceValidation.Proofs.Handlers.AeHoare
public import Consensus.TraceValidation.Proofs.Obligation
public import Consensus.TraceValidation.Proofs.Handlers.LifeHoare
public import Consensus.TraceValidation.Proofs.Handlers.AeLemmas
public import Consensus.TraceValidation.Proofs.Handlers.ReplUpdateCommit

@[expose] public section

/-!
# `send_append_entries` as a sequence of sub-range sends (not reviewed)

The loop of `send_append_entries` reads each sub-range end from the trace. Whatever the
ends, every successful run is a sequence of `send_append_entries_range` calls whose ends
lie within the view of their start (`maxEnd`), the first starting at the given index, each
next one just after the previous end, and the last ending at the last index.
-/

namespace Consensus.TraceValidation.Proofs.Repl

open Consensus.Model.Node
open Consensus.TraceValidation.Exec
open Consensus.TraceValidation.Proofs.Ae

/-- The highest sub-range end `send_append_entries` allows from `start`. -/
def maxEnd (v : State) (start : Nat) : Nat :=
  match v.endOfView (v.viewAt start) with
  | 0 => v.lastIdx
  | e => e

/-- The sub-range ends `send_append_entries` accepts from `start`. -/
def OkEnd (v : State) (start e : Nat) : Prop :=
  if start > maxEnd v start then e = maxEnd v start else start <= e /\ e <= maxEnd v start

/-- The request `send_append_entries_range` sends for the sub-range `[start, e]`. -/
def rangeRequest (names : Names) (v : State) (start e : Nat) : AppendEntriesRequest :=
  {
    term := v.currentView,
    prevLogIndex := start - 1,
    prevLogTerm := v.getTerm (start - 1),
    entries :=
      (List.range' start (e + 1 - start)).map fun i => absEntry names v.ledger[i - 1]!,
    primaryCommit := v.commitIdx
  }

/-! ## The sub-range ends (after the `Tick` proof's view lemmas) -/

/-- A list whose adjacent elements are ordered is sorted. -/
theorem pairwise_of_adjacent
    : forall {l : List Nat},
        (l.zip l.tail).all (fun (x, y) => decide (x <= y)) = true -> l.Pairwise (· <= ·)
  | [], _ => .nil
  | [_], _ => List.pairwise_singleton _ _
  | a :: b :: t, h => by
      simp only [List.tail_cons, List.zip_cons_cons, List.all_cons, Bool.and_eq_true,
        decide_eq_true_eq] at h
      have rest : (b :: t).Pairwise (· <= ·) := pairwise_of_adjacent (by simpa using h.2)
      refine List.Pairwise.cons ?_ rest
      intro x mem
      rcases List.mem_cons.mp mem with rfl | mem
      · exact h.1
      · exact Nat.le_trans h.1 (List.rel_of_pairwise_cons rest mem)

/-- In a sorted list, the `k`-th element is at most `i` iff more than `k` elements are. -/
theorem lt_length_filter_iff
    : forall {l : List Nat},
        l.Pairwise (· <= ·)
        -> forall {k : Nat} (hk : k < l.length) (i : Nat),
            k < (l.filter fun x => decide (x <= i)).length <-> l[k] <= i
  | [], _, k, hk, _ => by simp at hk
  | a :: t, sorted, k, hk, i => by
      have rest := List.Pairwise.of_cons sorted
      by_cases ai : a <= i
      · rw [List.filter_cons_of_pos (by simpa using ai), List.length_cons]
        cases k with
        | zero => simp [ai]
        | succ k =>
            simp only [List.getElem_cons_succ]
            have := lt_length_filter_iff rest (k := k) (by simpa using hk) i
            omega
      · rw [List.filter_cons_of_neg (by simpa using ai)]
        have none_ : (t.filter fun x => decide (x <= i)) = [] :=
          List.filter_eq_nil_iff.mpr fun y mem => by
            have := List.rel_of_pairwise_cons sorted mem
            simp only [decide_eq_true_eq]
            omega
        rw [none_]
        cases k with
        | zero => simp [ai]
        | succ k =>
            simp only [List.length_nil, Nat.not_lt_zero, false_iff, List.getElem_cons_succ]
            have := List.rel_of_pairwise_cons sorted (List.getElem_mem (l := t)
              (show k < t.length by simpa using hk))
            omega

/-- What the batch range needs of the view history, from `inv`. -/
structure ViewHyps (v : State) : Prop where
  size : v.ledger.size = v.lastIdx
  sorted : v.views.toList.Pairwise (· <= ·)
  positive : forall x, x ∈ v.views.toList -> 0 < x
  leLast : forall x, x ∈ v.views.toList -> x <= v.lastIdx + 1
  terms
    : forall i,
        1 <= i -> i <= v.lastIdx -> v.ledger[i - 1]?.map (·.term) = some (v.viewAt i)
  posTerms : forall e, e ∈ v.ledger.toList -> 0 < e.term

open Consensus.TraceValidation (Names) in
theorem ViewHyps.ofInv {names : Names} {v : State} (h : inv names v = true)
    : ViewHyps v := by
  obtain ⟨size, _, _, _, terms, _, positive⟩ := Ae.inv_parts h
  have sorted : (v.views.toList.zip v.views.toList.tail).all
      (fun (x, y) => decide (x <= y)) = true := by
    inv_conj h "views_sorted"
  have leLast : v.views.all (· <= v.lastIdx + 1) = true := by inv_conj h "views_le_last"
  have posTerms : v.ledger.all (0 < ·.term) = true := by inv_conj h "positive_terms"
  refine ⟨size, pairwise_of_adjacent sorted, ?_, ?_, terms, ?_⟩
  · intro x mem
    have := Array.all_eq_true_iff_forall_mem.mp positive x (by simpa using mem)
    simpa using this
  · intro x mem
    have := Array.all_eq_true_iff_forall_mem.mp leLast x (by simpa using mem)
    simpa using this
  · intro e mem
    have := Array.all_eq_true_iff_forall_mem.mp posTerms e (by simpa using mem)
    simpa using this

variable {v : State}

theorem viewAt_ge_iff (h : ViewHyps v) {k : Nat} (hk : k < v.views.size) (i : Nat)
    : k < v.viewAt i <-> v.views[k] <= i := by
  unfold State.viewAt
  have := lt_length_filter_iff h.sorted (k := k) (by simpa using hk) i
  simpa using this

theorem viewAt_pos (h : ViewHyps v) {i : Nat} (i1 : 1 <= i) (iL : i <= v.lastIdx)
    : 0 < v.viewAt i := by
  have t := h.terms i i1 iL
  have lt : i - 1 < v.ledger.size := by rw [h.size]; omega
  rw [Array.getElem?_eq_getElem lt] at t
  simp only [Option.map_some, Option.some.injEq] at t
  rw [← t]
  exact h.posTerms _ (by simp)

theorem viewAt_past (h : ViewHyps v) : v.viewAt (v.lastIdx + 1) = v.views.size := by
  unfold State.viewAt
  rw [List.filter_eq_self.mpr (fun x mem => by simpa using h.leLast x mem)]
  simp

/-- The range from `start` within the ledger: it ends in the ledger, in the view of `start`. -/
theorem maxIdx_range (h : ViewHyps v) {start : Nat} (s1 : 1 <= start)
    (sL : start <= v.lastIdx)
    : start <= maxEnd v start
      /\ maxEnd v start <= v.lastIdx
      /\ forall i, start <= i -> i <= maxEnd v start -> v.viewAt i = v.viewAt start := by
  have w1 := viewAt_pos h s1 sL
  have wS := ReplUpdateCommit.viewAt_le_size v start
  generalize hw : v.viewAt start = w at w1 wS
  have prevLe : v.views[w - 1] <= start :=
    (viewAt_ge_iff h (k := w - 1) (by omega) start).mp (by omega)
  have prevPos : 0 < v.views[w - 1] := h.positive _ (by simp)
  by_cases last : w < v.views.size
  · have nextGt : start < v.views[w] := by
      have := viewAt_ge_iff h (k := w) last start
      omega
    have nextLe : v.views[w] <= v.lastIdx + 1 := h.leLast _ (by simp)
    have eov : v.endOfView w = v.views[w] - 1 := by
      have ne : Not (v.views[w] = v.views[w - 1]) := by omega
      simp [State.endOfView, State.startOfView, last, Nat.not_lt.mpr (Nat.le_of_lt last),
        Nat.ne_of_gt w1, ne, Nat.succ_le_of_lt last,
        getElem!_pos v.views (w - 1) (by omega), Nat.ne_of_gt prevPos, Nat.not_le.mpr last]
    have mx : maxEnd v start = v.views[w] - 1 := by
      unfold maxEnd
      rw [hw, eov]
      split
      · omega
      · rfl
    rw [mx]
    refine ⟨by omega, by omega, fun i si im => ?_⟩
    have lo := ReplUpdateCommit.viewAt_mono v si
    have hi : Not (w < v.viewAt i) := fun lt => by
      have := (viewAt_ge_iff h last i).mp lt
      omega
    omega
  · have eq : w = v.views.size := by omega
    have eov : v.endOfView w = 0 := by
      simp [State.endOfView, eq]
    have mx : maxEnd v start = v.lastIdx := by
      unfold maxEnd
      rw [hw, eov]
      rfl
    rw [mx]
    refine ⟨sL, Nat.le_refl _, fun i si _ => ?_⟩
    have lo := ReplUpdateCommit.viewAt_mono v si
    have hi := ReplUpdateCommit.viewAt_le_size v i
    omega

/-- From one past the ledger, the range is empty: it ends at the last index. -/
theorem maxIdx_past (h : ViewHyps v) : maxEnd v (v.lastIdx + 1) = v.lastIdx := by
  unfold maxEnd
  rw [viewAt_past h]
  have eov : v.endOfView v.views.size = 0 := by simp [State.endOfView]
  rw [eov]
  rfl

variable {env : Env}

theorem tri_of_hoare {α : Type} {P : State -> Outbox -> Prop} {x : M α}
    {Q : α -> State -> Outbox -> Prop} (h : Hoare env P x Q)
    : Life.Tri env P x Q :=
  h

theorem sendRange_spec {to : NodeId} {start e : Nat} {ext : Bool} {v0 : State}
    {o0 : Outbox} {p : Peer} (found : v0.peer? to = some p)
    : Hoare env (fun v o => v = v0 /\ o = o0) (sendAppendEntriesRange to start e ext)
        fun _ v o =>
          v = v0.setPeer to { p with sentIdx := e }
          /\ o
              = o0
                ++ [⟨
                      env.names.id v0.nodeId,
                      env.names.id to,
                      .appendEntriesRequest (rangeRequest env.names v0 start e)
                    ⟩] := by
  unfold sendAppendEntriesRange
  refine Hoare.getV_bind fun s => ?_
  refine Hoare.pin fun v o pre => ?_
  obtain ⟨⟨hv, ho⟩, hs⟩ := pre
  subst s; subst v; subst o
  simp only [found]
  refine Hoare.bind (Hoare.keeps (Spec.emit _ _) fun _ _ _ h => h) fun _ => ?_
  refine Hoare.bind (Hoare.keeps (Spec.emitStr _ _) fun _ _ _ h => h) fun _ => ?_
  refine Hoare.bind (Hoare.of_spec Spec.names
    (Q := fun a w o => a = env.names /\ w = v0 /\ o = o0) fun _ _ _ _ _ p h => by
      obtain ⟨rfl, rfl⟩ := p
      exact ⟨h.1, h.2.1, h.2.2⟩) fun names => ?_
  refine Hoare.pin fun w o pre => ?_
  obtain ⟨hn, hw, ho⟩ := pre
  subst names; subst w; subst o
  refine Hoare.bind (Hoare.send _ _ (Q := fun _ w o' => w = v0 /\ o' = o0 ++ [⟨env.names.id v0.nodeId, env.names.id to,
                .appendEntriesRequest (rangeRequest env.names v0 start e)⟩]) fun _ _ h => by
      obtain ⟨rfl, rfl⟩ := h
      exact ⟨rfl, rfl⟩) fun _ => ?_
  refine Hoare.bind (Hoare.keeps (Spec.note _) fun _ _ _ h => h) fun _ => ?_
  exact Hoare.setV _ fun _ _ h => by obtain ⟨rfl, rfl⟩ := h; exact ⟨rfl, rfl⟩

open Consensus.TraceValidation.Proofs.Life in
theorem tri_fact {α : Type} {x : M α} {P : State -> Outbox -> Prop}
    {Q : α -> State -> Outbox -> Prop} {φ : Prop} (get : forall v o, P v o -> φ)
    (h : φ -> Tri env P x Q)
    : Tri env P x Q :=
  fun c a c' e p r => h (get _ _ p) c a c' e p r

theorem okEnd_of {v : State} {start e : Nat}
    (h
      : (if start > maxEnd v start then
            e == maxEnd v start
          else
            decide (start <= e) && decide (e <= maxEnd v start))
        = true)
    : OkEnd v start e := by
  unfold OkEnd
  split at h
  · simp_all
  · rename_i hs
    simp only [Bool.and_eq_true, decide_eq_true_eq] at h
    simp only [gt_iff_lt, hs, ite_false]
    exact h

open Consensus.TraceValidation.Proofs.Life in
theorem loop_tri {to : NodeId} {ext : Bool} {I : Nat -> State -> Outbox -> Prop}
    {Fin : State -> Outbox -> Prop}
    (notRC : forall s v o, I s v o -> v.isRetiredCommitted = false)
    (step
      : forall s e,
          Tri env (fun v o => I s v o /\ OkEnd v s e)
            (sendAppendEntriesRange to s e ext)
            fun _ v o =>
              (e = v.lastIdx -> Fin v o)
              /\ (e ≠ v.lastIdx -> I (min (e + 1) v.lastIdx) v o))
    : forall fuel start batch,
        Tri env (I start) (sendAppendEntries.loop to ext fuel start batch)
          fun _ => Fin := by
  intro fuel
  induction fuel with
  | zero =>
      intro start batch
      unfold sendAppendEntries.loop
      exact Tri.bind (Tri.keeps Spec.curLoc) fun _ => Tri.fail _
  | succ fuel ih =>
      intro start batch
      unfold sendAppendEntries.loop
      refine Tri.getV_bind fun v => ?_
      refine tri_fact (fun w o p => p.2 ▸ notRC _ _ _ p.1) fun hrc => ?_
      simp only [hrc, Bool.false_and, Bool.false_eq_true, ite_false, pure_bind]
      have hK : forall e b, Tri env (fun w o => (I start w o /\ w = v) /\ OkEnd v start e)
          (do
            sendAppendEntriesRange to start e ext
            let v ← getV
            if (e == v.lastIdx) = true then pure ()
              else sendAppendEntries.loop to ext fuel (min (e + 1) v.lastIdx) b) fun _ => Fin := by
        intro e b
        refine Tri.bind (Tri.conseq (step start e) (fun w o h => ⟨h.1.1, h.1.2 ▸ h.2⟩)
          (fun _ _ _ h => h)) fun _ => ?_
        refine Tri.getV_bind fun w => ?_
        refine Tri.ite (fun he => ?_) (fun he => ?_)
        · exact Tri.conseq (Tri.pure' (Q := fun _ => Fin) ()) (fun _ _ h => by
            obtain ⟨h, rfl⟩ := h
            exact h.1 (by simpa using he)) (fun _ _ _ h => h)
        · exact Tri.conseq (ih _ _) (fun _ _ h => by
            obtain ⟨h, rfl⟩ := h
            exact h.2 (by simpa using he)) (fun _ _ _ h => h)
      refine Tri.bind (Q := fun _ w o => I start w o /\ w = v) (Tri.keeps Spec.look)
        fun _ => ?_
      refine Tri.bind (Tri.keeps (Spec.trace _)) fun _ => ?_
      refine Tri.bind (Tri.keeps (Spec.use _)) fun _ => ?_
      refine Tri.bind (Tri.keeps (Spec.liftE _)) fun e => ?_
      refine Tri.ite (fun hok => ?_)
        (fun _ => Tri.bind (Tri.keeps Spec.curLoc) fun _ => Tri.fail_bind _)
      have ok : OkEnd v start e := okEnd_of hok
      refine Tri.conseq (P' := fun w o => (I start w o /\ w = v) /\ OkEnd v start e) ?_
        (fun _ _ h => ⟨h, ok⟩) (fun _ _ _ h => h)
      have hF : forall {β : Type} (m : String -> String) (k : Unit -> M β) {Q : β -> State -> Outbox -> Prop},
          Tri env (fun w o => (I start w o /\ w = v) /\ OkEnd v start e)
            (curLoc >>= fun l => fail (m l) >>= k) Q :=
        fun _ _ => Tri.bind (Tri.keeps Spec.curLoc) fun _ => Tri.fail_bind _
      refine Tri.ite (fun _ => Tri.ite (fun _ => hF _ _) fun _ => hK _ _)
        fun _ => Tri.ite (fun _ => hF _ _) fun _ => hK _ _

open Consensus.TraceValidation.Proofs.Life in
theorem send_tri {to : NodeId} {start : Nat} {ext : Bool}
    {I : Nat -> State -> Outbox -> Prop} {Fin : State -> Outbox -> Prop}
    (notRC : forall s v o, I s v o -> v.isRetiredCommitted = false)
    (step
      : forall s e,
          Tri env (fun v o => I s v o /\ OkEnd v s e)
            (sendAppendEntriesRange to s e ext)
            fun _ v o =>
              (e = v.lastIdx -> Fin v o)
              /\ (e ≠ v.lastIdx -> I (min (e + 1) v.lastIdx) v o))
    : Tri env (I start) (sendAppendEntries to start ext) fun _ => Fin := by
  unfold sendAppendEntries
  refine Tri.getV_bind fun v => ?_
  exact Tri.conseq (loop_tri notRC step _ _ _) (fun _ _ h => h.1) (fun _ _ _ h => h)

theorem setPeer_lastIdx (v : State) (id : NodeId) (p : Peer)
    : (v.setPeer id p).lastIdx = v.lastIdx :=
  rfl

/-- A heartbeat from one past the ledger: one empty request, the peer's send index at the end. -/
theorem heartbeat_tri {to : NodeId} {ext : Bool} {v0 : State} {o0 : Outbox} {p : Peer}
    (h : ViewHyps v0) (rc : v0.isRetiredCommitted = false) (found : v0.peer? to = some p)
    : Life.Tri env (fun v o => v = v0 /\ o = o0)
        (sendAppendEntries to (v0.lastIdx + 1) ext)
        fun _ v o =>
          v = v0.setPeer to { p with sentIdx := v0.lastIdx }
          /\ o
              = o0
                ++ [⟨
                      env.names.id v0.nodeId,
                      env.names.id to,
                      .appendEntriesRequest
                        (rangeRequest env.names v0 (v0.lastIdx + 1) v0.lastIdx)
                    ⟩] := by
  refine Life.Tri.conseq (send_tri (start := v0.lastIdx + 1)
    (I := fun s v o => s = v0.lastIdx + 1 /\ v = v0 /\ o = o0) (fun _ _ _ h => h.2.1 ▸ rc)
    (fun s e => ?_)) (fun _ _ h => ⟨rfl, h⟩) (fun _ _ _ h => h)
  refine tri_fact (φ := s = v0.lastIdx + 1 /\ e = v0.lastIdx) (fun v o h => by
    obtain ⟨⟨rfl, rfl, _⟩, ok⟩ := h
    refine ⟨rfl, ?_⟩
    unfold OkEnd at ok
    rw [maxIdx_past h] at ok
    simpa using ok) fun ⟨hs, he⟩ => ?_
  subst hs he
  refine Life.Tri.conseq (tri_of_hoare <| sendRange_spec (env := env) (start := v0.lastIdx + 1) (e := v0.lastIdx) (ext := ext) (o0 := o0) found)
    (fun _ _ h => ⟨h.1.2.1, h.1.2.2⟩) (fun _ _ _ h => ?_)
  obtain ⟨rfl, rfl⟩ := h
  exact ⟨fun _ => ⟨rfl, rfl⟩, fun ne => absurd rfl ne⟩

end Consensus.TraceValidation.Proofs.Repl
