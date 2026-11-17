module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.TraceValidation.Proofs.Handlers.AeLemmas
public import CCF.Proofs.Finset

@[expose] public section

/-!
# The clean AppendEntries handler in closed form (not reviewed)

`handleAppendEntiresFromPrimary` appends the new entries and commits at each signature and
at the end. Its result is `settle`: the extended log, the commit index
`max ci (maxCommittableIndexUpTo log limit)`, and the retirement latch that `recordCommit`
derives from the committed prefix (`firstConf`), clearing the role when it latches. Also: the
first term conflict of a request whose entries share one term, and the round trip of
received entries through the declared ledger.
-/

namespace Consensus.TraceValidation.Proofs.Ae

open Consensus.Model.Node
theorem find?_prefix {α : Type} {l₁ l₂ : List α} {p : α -> Bool} (h : l₁ <+: l₂) {x : α}
    (hx : l₁.find? p = some x)
    : l₂.find? p = some x := by
  obtain ⟨t, rfl⟩ := h
  simp [List.find?_append, hx]

theorem zipIdx_prefix {α : Type} {l₁ l₂ : List α} (h : l₁ <+: l₂) (k : Nat)
    : l₁.zipIdx k <+: l₂.zipIdx k := by
  obtain ⟨t, rfl⟩ := h
  rw [List.zipIdx_append]
  exact List.prefix_append _ _

theorem take_prefix_take {α : Type} {l₁ l₂ : List α} (h : l₁ <+: l₂) {a b : Nat}
    (ab : a <= b)
    : l₁.take a <+: l₂.take b :=
  List.prefix_take_iff.mpr ⟨(List.take_prefix a l₁).trans h, by simp; omega⟩

theorem fla_prefix {l₁ l₂ : List Entry} (h : l₁ <+: l₂) {a : Nat}
    {p : EntryContent -> Bool} {x : Nat} (hx : firstLogIndexAfter l₁ a p = some x)
    : firstLogIndexAfter l₂ a p = some x := by
  unfold firstLogIndexAfter at *
  obtain ⟨y, hy, rfl⟩ := Option.map_eq_some_iff.mp hx
  rw [find?_prefix (zipIdx_prefix h 1) hy]
  rfl

theorem fla_le {l : List Entry} {a : Nat} {p : EntryContent -> Bool} {x : Nat}
    (hx : firstLogIndexAfter l a p = some x)
    : 1 <= x /\ x <= l.length := by
  unfold firstLogIndexAfter at hx
  obtain ⟨⟨e, i⟩, hy, rfl⟩ := Option.map_eq_some_iff.mp hx
  have := List.mem_zipIdx (List.mem_of_find?_eq_some hy)
  dsimp only
  omega

theorem zip_tail_prefix {α : Type}
    : forall {A B : List α}, A <+: B -> A.zip A.tail <+: B.zip B.tail
  | [], _, _ => by simp
  | [_], _, _ => by simp
  | a :: a2 :: A, B, h => by
      obtain ⟨t, rfl⟩ := h
      have ih := zip_tail_prefix (A := a2 :: A) (B := a2 :: A ++ t) (List.prefix_append _ _)
      simp only [List.tail_cons, List.cons_append, List.zip_cons_cons] at ih ⊢
      exact List.cons_prefix_cons.mpr ⟨rfl, ih⟩

theorem configurationHistory_prefix {l₁ l₂ : List Entry} (h : l₁ <+: l₂)
    : configurationHistory l₁ <+: configurationHistory l₂ :=
  (zipIdx_prefix h 1).filterMap _

theorem rii_prefix {n : NodeID} {l₁ l₂ : List Entry} (h : l₁ <+: l₂)
    (hx : (retirementIndexInLog n l₁).isSome)
    : (retirementIndexInLog n l₂).isSome := by
  unfold retirementIndexInLog at *
  dsimp only at *
  obtain ⟨y, hy⟩ := Option.isSome_iff_exists.mp hx
  obtain ⟨z, hz, rfl⟩ := Option.map_eq_some_iff.mp hy
  rw [find?_prefix (zip_tail_prefix (configurationHistory_prefix h)) hz]
  rfl

/-! ## `maxCommittableIndex` -/

theorem mcI_cases (l : List Entry)
    : maxCommittableIndex l = 0 \/ isSignatureAt l (maxCommittableIndex l) = true :=
  foldMax_cases (isSignatureAt l) _ 0

theorem le_mcI {l : List Entry} {i : Nat} (h : isSignatureAt l i = true)
    : i <= maxCommittableIndex l :=
  foldMax_ge_mem _ _ _ _
    (List.mem_range.mpr (Nat.lt_succ_of_le (isSignatureAt_le_length h))) h

theorem mcI_le_length (l : List Entry) : maxCommittableIndex l <= l.length := by
  rcases mcI_cases l with h | h
  · omega
  · exact isSignatureAt_le_length h

theorem isSignatureAt_prefix {l₁ l₂ : List Entry} (h : l₁ <+: l₂) {i : Nat}
    (hi : isSignatureAt l₁ i = true)
    : isSignatureAt l₂ i = true := by
  have hl := isSignatureAt_le_length hi
  unfold isSignatureAt entryAt? at hi ⊢
  by_cases i0 : i = 0
  · simp [i0] at hi
  · simp only [i0, ite_false] at hi ⊢
    have lt : i - 1 < l₁.length := by omega
    rw [List.getElem?_eq_getElem lt] at hi
    rw [List.getElem?_eq_getElem (Nat.lt_of_lt_of_le lt h.length_le), ← h.getElem lt]
    exact hi

theorem mcI_prefix {l₁ l₂ : List Entry} (h : l₁ <+: l₂)
    : maxCommittableIndex l₁ <= maxCommittableIndex l₂ := by
  rcases mcI_cases l₁ with e | e
  · omega
  · exact le_mcI (isSignatureAt_prefix h e)

theorem mcIUpTo_le (l : List Entry) (lim : Nat)
    : maxCommittableIndexUpTo l lim <= lim
      /\ maxCommittableIndexUpTo l lim <= l.length := by
  have := mcI_le_length (l.take lim)
  simp only [maxCommittableIndexUpTo, List.length_take] at *
  omega

theorem mcIUpTo_prefix {l₁ l₂ : List Entry} (h : l₁ <+: l₂) (lim : Nat)
    : maxCommittableIndexUpTo l₁ lim <= maxCommittableIndexUpTo l₂ lim :=
  mcI_prefix (take_prefix_take h (Nat.le_refl _))

/-! ## The commits of `handleAppendEntiresFromPrimary` in closed form -/

/-- What `recordCommit` latches at commit index `ci` of `l`. -/
def firstConf (node : NodeID) (l : List Entry) (ci : Nat) : Option Nat :=
  firstLogIndexAfter (l.take ci) 0
    fun content => decide (node ∈ content.metadata.retirementConfirmations)

/--
`s` with log `log` and commit index `ci`, after the commits in between: the latch is the
first committed confirmation, and the role and primary knowledge clear if it was unset.
-/
def settle (node : NodeID) (s : NodeState) (log : List Entry) (ci : Nat) : NodeState :=
  let rci := firstConf node log ci
  let cleared := s.retiredCommittedIndex.isNone && rci.isSome
  {
    s with
      log
      commitIndex := ci
      retiredCommittedIndex := rci
      role := if cleared then .none else s.role
      primaryKnown := if cleared then false else s.primaryKnown
  }

theorem isRetiredCommitted_iff (node : NodeID) (s : NodeState)
    : s.isRetiredCommitted node
      <-> (retirementIndexInLog node s.log).isSome /\ s.retiredCommittedIndex.isSome := by
  unfold NodeState.isRetiredCommitted NodeState.retirement
  dsimp only
  cases retirementIndexInLog node s.log with
  | none => simp
  | some i =>
      simp only [Option.isSome_some, true_and]
      split <;> simp_all <;> split <;> simp_all <;> split <;> simp_all

theorem firstConf_mono {node : NodeID} {L L' : List Entry} {C C' x : Nat}
    (h : firstConf node L C = some x) (hl : L.take C <+: L'.take C')
    : firstConf node L' C' = some x :=
  fla_prefix hl h

theorem firstConf_le {node : NodeID} {L : List Entry} {C x : Nat}
    (h : firstConf node L C = some x)
    : 1 <= x /\ x <= C /\ x <= L.length := by
  have := fla_le h
  simp only [List.length_take] at this
  omega

theorem recordCommit_settle {node : NodeID} {s : NodeState} {L : List Entry} {C C' : Nat}
    (hs : s.retiredCommittedIndex = firstConf node s.log s.commitIndex)
    (hsl : s.log.take s.commitIndex <+: L.take C) (hC : C <= C')
    (hR
      : forall j,
          firstConf node L C' = some j -> (retirementIndexInLog node (L.take j)).isSome)
    : (settle node s L C).recordCommit node C' = settle node s L C' := by
  have mono : L.take C <+: L.take C' := take_prefix_take (List.prefix_refl L) hC
  cases h1 : firstConf node L C with
  | some x =>
      have h2 := firstConf_mono h1 mono
      unfold NodeState.recordCommit settle
      simp only [h1, h2, Option.isSome_some, Option.orElse_some, Bool.and_true,
        Bool.not_true]
      rfl
  | none =>
      have s0 : s.retiredCommittedIndex = none := by
        cases h0 : s.retiredCommittedIndex with
        | none => rfl
        | some y =>
            rw [h0] at hs
            have := firstConf_mono hs.symm (by simpa [List.take_take] using hsl)
            rw [h1] at this
            cases this
      cases h2 : firstConf node L C' with
      | none =>
          unfold NodeState.recordCommit settle firstConf at *
          simp only [h1, h2, s0, Option.isSome_none, Bool.and_false, Option.orElse_none,
            Bool.false_eq_true, ite_false, Bool.not_false, isRetiredCommitted_iff,
            and_false]
      | some j =>
          have rj := hR j h2
          have rL : (retirementIndexInLog node L).isSome := rii_prefix (List.take_prefix j L) rj
          unfold NodeState.recordCommit settle firstConf at *
          simp only [h1, h2, s0, Option.isSome_none, Bool.and_false, Option.orElse_none,
            Bool.false_eq_true, ite_false, Bool.not_false, isRetiredCommitted_iff,
            Option.isSome_some, and_true, rL, Option.isNone_none, Bool.and_self, ite_true]

/-- `commitIfPossible` of `handleAppendEntiresFromPrimary`. -/
def cip (node : NodeID) (lim : Nat) (s : NodeState) : NodeState :=
  s.recordCommit node (max s.commitIndex (maxCommittableIndexUpTo s.log lim))

/-- The log append of one step of the entry fold of `handleAppendEntiresFromPrimary`. -/
def appendLog (s : NodeState) (e : Entry) : NodeState := { s with log := s.log ++ [e] }

/-- One step of the entry fold of `handleAppendEntiresFromPrimary`. -/
def aeStep (node : NodeID) (lim : Nat) (s : NodeState) (e : Entry) : NodeState :=
  if e.content.isSignature then cip node lim (appendLog s e) else appendLog s e

theorem fromPrimary_unfold (node : NodeID) (s : NodeState) (r : AppendEntriesRequest)
    : handleAppendEntiresFromPrimary node s r
      = let fin :=
          cip node (min r.primaryCommit (r.prevLogIndex + r.entries.length))
            ((r.entries.drop (s.log.length - r.prevLogIndex)).foldl
              (aeStep node (min r.primaryCommit (r.prevLogIndex + r.entries.length))) s)
        (
          fin,
          {
            term := fin.currentTerm
            success := true
            lastLogIndex := r.prevLogIndex + r.entries.length
          }
        ) :=
  rfl

theorem settle_log (node : NodeID) (s : NodeState) {L : List Entry} {C : Nat}
    (e : Entry) (hC : C <= L.length)
    : appendLog (settle node s L C) e = settle node s (L ++ [e]) C := by
  have : firstConf node (L ++ [e]) C = firstConf node L C := by
    simp [firstConf, List.take_append_of_le_length hC]
  simp only [appendLog, settle, this]

theorem settle_self (node : NodeID) (s : NodeState)
    (hs : s.retiredCommittedIndex = firstConf node s.log s.commitIndex)
    : settle node s s.log s.commitIndex = s := by
  cases s with
  | mk role ct log ci si mi nf vf pk vg pvg rci =>
      simp only at hs
      unfold settle
      simp only
      rw [← hs]
      cases rci <;> simp

theorem fold_settle (node : NodeID) (lim : Nat) (s : NodeState) (Lf : List Entry)
    (Cf : Nat) (hs : s.retiredCommittedIndex = firstConf node s.log s.commitIndex)
    (hR
      : forall j,
          firstConf node Lf Cf = some j -> (retirementIndexInLog node (Lf.take j)).isSome)
    : forall (es L : List Entry) (C : Nat),
        L ++ es = Lf
        -> s.log.take s.commitIndex <+: L.take C
        -> C <= L.length
        -> max C (maxCommittableIndexUpTo Lf lim) <= Cf
        -> exists C',
            C <= C'
            /\ C' <= max C (maxCommittableIndexUpTo Lf lim)
            /\ C' <= Lf.length
            /\ es.foldl (aeStep node lim) (settle node s L C) = settle node s Lf C' := by
  intro es
  induction es with
  | nil =>
      intro L C hL hp hC hCf
      simp only [List.append_nil] at hL
      subst hL
      exact ⟨C, Nat.le_refl _, Nat.le_max_left _ _, hC, rfl⟩
  | cons e es ih =>
      intro L C hL hp hC hCf
      have hL' : (L ++ [e]) ++ es = Lf := by simp [← hL]
      have pre : L ++ [e] <+: Lf := ⟨es, hL'⟩
      have up := mcIUpTo_prefix pre lim
      have upL := (mcIUpTo_le (L ++ [e]) lim).2
      have lenL : (L ++ [e]).length = L.length + 1 := by simp
      have hp' : s.log.take s.commitIndex <+: (L ++ [e]).take C :=
        hp.trans (take_prefix_take (List.prefix_append _ _) (Nat.le_refl _))
      simp only [List.foldl_cons]
      have st : aeStep node lim (settle node s L C) e
          = if e.content.isSignature then cip node lim (settle node s (L ++ [e]) C)
            else settle node s (L ++ [e]) C := by
        unfold aeStep
        rw [settle_log node s e hC]
      rw [st]
      split
      · let C2 := max C (maxCommittableIndexUpTo (L ++ [e]) lim)
        have c2 : cip node lim (settle node s (L ++ [e]) C) = settle node s (L ++ [e]) C2 := by
          have e1 : cip node lim (settle node s (L ++ [e]) C)
              = (settle node s (L ++ [e]) C).recordCommit node C2 := rfl
          rw [e1]
          refine recordCommit_settle hs hp' (Nat.le_max_left _ _) fun j hj => ?_
          have big : firstConf node Lf Cf = some j :=
            firstConf_mono hj (take_prefix_take pre (by omega))
          have hjle := firstConf_le hj
          have := hR j big
          have eq : Lf.take j = (L ++ [e]).take j := by
            rw [← hL']
            exact List.take_append_of_le_length (by omega)
          rwa [eq] at this
        rw [c2]
        obtain ⟨C', a, b, c, d⟩ := ih (L ++ [e]) C2 hL'
          (hp.trans (take_prefix_take (List.prefix_append _ _) (Nat.le_max_left _ _)))
          (by omega) (by omega)
        exact ⟨C', by omega, by omega, c, d⟩
      · obtain ⟨C', a, b, c, d⟩ := ih (L ++ [e]) C hL' hp' (by omega) hCf
        exact ⟨C', a, b, c, d⟩

theorem fromPrimary_eq (node : NodeID) (s : NodeState) (r : AppendEntriesRequest)
    (hs : s.retiredCommittedIndex = firstConf node s.log s.commitIndex)
    (hci : s.commitIndex <= s.log.length)
    (hR
      : forall j,
          firstConf node (s.log ++ r.entries.drop (s.log.length - r.prevLogIndex))
              (max s.commitIndex
                (maxCommittableIndexUpTo
                  (s.log ++ r.entries.drop (s.log.length - r.prevLogIndex))
                  (min r.primaryCommit (r.prevLogIndex + r.entries.length))))
            = some j
          -> (retirementIndexInLog node
                ((s.log ++ r.entries.drop (s.log.length - r.prevLogIndex)).take
                  j)).isSome)
    : handleAppendEntiresFromPrimary node s r
      = (
        settle node s (s.log ++ r.entries.drop (s.log.length - r.prevLogIndex))
          (max s.commitIndex
            (maxCommittableIndexUpTo
              (s.log ++ r.entries.drop (s.log.length - r.prevLogIndex))
              (min r.primaryCommit (r.prevLogIndex + r.entries.length)))),
        {
          term := s.currentTerm
          success := true
          lastLogIndex := r.prevLogIndex + r.entries.length
        }
      ) := by
  generalize hlim : min r.primaryCommit (r.prevLogIndex + r.entries.length) = lim at *
  generalize hes : r.entries.drop (s.log.length - r.prevLogIndex) = es at *
  rw [fromPrimary_unfold, hlim, hes]
  obtain ⟨C', a, b, c, d⟩ := fold_settle node lim s _ _ hs hR es s.log s.commitIndex rfl
    (List.prefix_refl _) hci (Nat.le_refl _)
  rw [settle_self node s hs] at d
  have up := (mcIUpTo_le (s.log ++ es) lim).2
  have e2 : max C' (maxCommittableIndexUpTo (s.log ++ es) lim)
      = max s.commitIndex (maxCommittableIndexUpTo (s.log ++ es) lim) := by omega
  have fin : cip node lim (settle node s (s.log ++ es) C')
      = settle node s (s.log ++ es)
          (max s.commitIndex (maxCommittableIndexUpTo (s.log ++ es) lim)) := by
    have e1 : cip node lim (settle node s (s.log ++ es) C')
        = (settle node s (s.log ++ es) C').recordCommit node
            (max C' (maxCommittableIndexUpTo (s.log ++ es) lim)) := rfl
    rw [e1, recordCommit_settle (L := s.log ++ es) hs
      (take_prefix_take (List.prefix_append _ _) a) (Nat.le_max_left _ _)
      (by rw [e2]; exact hR), e2]
  simp only [d, fin]
  rfl

theorem set_name_sort (names : Names) (s : CCF.Finset NodeID)
    (h : s.sort.all (fun i => names.id (names.name i) == i) = true)
    : names.set (s.sort.map names.name) = s := by
  apply CCF.Finset.ext
  intro a
  simp only [Names.set, CCF.Finset.mem_ofList, List.map_map]
  have : (s.sort.map (names.id ∘ names.name)) = s.sort := by
    conv => rhs; rw [← List.map_id s.sort]
    apply List.map_congr_left
    intro i hi
    simp only [List.all_eq_true, beq_iff_eq] at h
    exact h i hi
  rw [this, CCF.Finset.mem_sort]

theorem absEntry_toExecEntry (env : Env) (e : Entry)
    (hq
      : (match e.content with
          | .transaction q _ => q == 0
          | .signature => true)
        = true)
    (hn
      : (((e.content.metadata.configuration.map (·.sort)).getD []
          ++ e.content.metadata.retirementConfirmations.sort).all
          fun i => env.names.id (env.names.name i) == i)
        = true)
    : absEntry env.names (Exec.toExecEntry env e) = e := by
  obtain ⟨t, c⟩ := e
  cases c with
  | signature => rfl
  | transaction q md =>
      obtain ⟨cfg, rc⟩ := md
      simp only [beq_iff_eq] at hq
      subst hq
      simp only [EntryContent.metadata, List.all_append, Bool.and_eq_true] at hn
      simp only [absEntry, Exec.toExecEntry, Bool.false_eq_true, ite_false]
      congr
      · cases cfg with
        | none => rfl
        | some s =>
            simp only [Option.map_some, Option.getD_some] at hn
            simp only [Option.map_some, Exec.envNodes, List.map_map, Function.comp_def,
              Option.some.injEq]
            exact set_name_sort env.names s hn.1
      · exact set_name_sort env.names rc hn.2

theorem ftci_at (L : List Entry) (es : List Entry) (p n : Nat)
    (hn : n < (((L.drop p).zip es).zipIdx (p + 1)).length)
    : (((L.drop p).zip es).zipIdx (p + 1))[n]
      = ((L[p + n]'(by simp at hn; omega), es[n]'(by simp at hn; omega)), p + 1 + n) := by
  simp [List.getElem_zipIdx]

theorem termAt_get (L : List Entry) (j : Nat) (h1 : 0 < j) (h2 : j <= L.length)
    : termAt L j = (L[j - 1]'(by omega)).term := by
  simp only [termAt, entryAt?, Nat.ne_of_gt h1, ite_false]
  rw [List.getElem?_eq_getElem (by omega)]
  rfl

theorem ftci_spec (s : NodeState) (r : AppendEntriesRequest) (τ : Nat)
    (hτ : forall e, e ∈ r.entries -> e.term = τ)
    : match firstTermConflictIndex s r with
      | some k =>
          r.prevLogIndex < k
          /\ k <= s.log.length
          /\ k <= r.prevLogIndex + r.entries.length
          /\ termAt s.log k ≠ τ
          /\ forall j, r.prevLogIndex < j -> j < k -> termAt s.log j = τ
      | none =>
          forall j,
            r.prevLogIndex < j
            -> j <= s.log.length
            -> j <= r.prevLogIndex + r.entries.length
            -> termAt s.log j = τ := by
  unfold firstTermConflictIndex
  generalize hp : r.prevLogIndex = p
  generalize hes : r.entries = es at hτ
  generalize hL : s.log = L
  simp only
  have len : (((L.drop p).zip es).zipIdx (p + 1)).length = min (L.length - p) es.length := by
    simp
  -- the element at position `n` is the comparison at index `p + 1 + n`
  have key : forall n (hn : n < min (L.length - p) es.length),
      termAt L (p + 1 + n) = (L[p + n]'(by omega)).term
      /\ (es[n]'(by omega)).term = τ := by
    intro n hn
    refine ⟨?_, hτ _ (List.getElem_mem _)⟩
    rw [termAt_get L _ (by omega) (by omega)]
    congr 2
    omega
  cases h
        : (((L.drop p).zip es).zipIdx (p + 1)).find?
            (fun x => x.1.1.term != x.1.2.term) with
  | none =>
      simp only [Option.map_none]
      intro j pj jL jr
      rw [List.find?_eq_none] at h
      have hn : j - p - 1 < (((L.drop p).zip es).zipIdx (p + 1)).length := by
        rw [len]; omega
      have := h _ (List.getElem_mem hn)
      rw [ftci_at L es p _ hn] at this
      simp only [bne_iff_ne, ne_eq, Decidable.not_not] at this
      obtain ⟨k1, k2⟩ := key (j - p - 1) (by rw [← len]; exact hn)
      have e : p + 1 + (j - p - 1) = j := by omega
      rw [e] at k1
      rw [k1, this, k2]
  | some x =>
      simp only [Option.map_some]
      rw [List.find?_eq_some_iff_getElem] at h
      obtain ⟨px, n, hn, hx, before⟩ := h
      rw [ftci_at L es p _ hn] at hx
      subst hx
      have hn' : n < min (L.length - p) es.length := by rw [← len]; exact hn
      obtain ⟨k1, k2⟩ := key n hn'
      simp only [bne_iff_ne, ne_eq] at px
      refine ⟨by omega, by omega, by omega, by rw [k1, ← k2]; exact px, ?_⟩
      intro j pj jk
      have hm : j - p - 1 < n := by omega
      have := before (j - p - 1) hm
      rw [ftci_at L es p _ (by omega)] at this
      simp only [Bool.not_eq_true', bne_eq_false_iff_eq] at this
      obtain ⟨m1, m2⟩ := key (j - p - 1) (by omega)
      have e : p + 1 + (j - p - 1) = j := by omega
      rw [e] at m1
      rw [m1, this, m2]

end Consensus.TraceValidation.Proofs.Ae
