module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.TraceValidation.Proofs.Monad
public import Consensus.TraceValidation.MTv.Invariant
public import CCF.Proofs.Finset

@[expose] public section

/-!
# `update_commit` chooses the clean `highestCommittableIndex` (not reviewed)

Shared by the `Repl` and `AeResp` handler proofs. M_tv's `update_commit` loop
(`Exec.updateCommitGo`, mirrored purely by `updateCommitOf`) walks the active
configurations in order and commits the highest index that every configuration's
majority has confirmed. On a declared state satisfying `inv`, the result is the clean
`highestCommittableIndex` of the abstracted state:

* `updateCommitGo_spec`: the monadic loop reads the state, changes nothing and returns
  `updateCommitOf`;
* `updateCommit_eq_of_inv`: `inv names v = true` and `updateCommitOf v 0 none fuel = .ok r`
  give `highestCommittableIndex (abs names v) (names.id v.nodeId) = r.getD v.commitIdx`
  (`none` means no index to commit, and the clean index is the current commit index).
-/

namespace Consensus.TraceValidation.Proofs.ReplUpdateCommit

/-! ## The median of sorted match indexes -/

theorem sorted_le {s : List Nat} (sorted : s.Pairwise (· ≤ ·)) {i j : Nat} (ij : i ≤ j)
    (hj : j < s.length)
    : s[i]'(Nat.lt_of_le_of_lt ij hj) ≤ s[j] := by
  rcases Nat.lt_or_eq_of_le ij with lt | rfl
  · exact List.pairwise_iff_getElem.mp sorted i j _ hj lt
  · exact Nat.le_refl _

/--
In a sorted list, the element at `(n - 1) / 2` is the largest `t` that more than half of
the elements reach.
-/
theorem sorted_median_iff {s : List Nat} (sorted : s.Pairwise (· ≤ ·)) {x : Nat}
    (median : s[(s.length - 1) / 2]? = some x) (t : Nat)
    : s.countP (fun m => decide (t ≤ m)) * 2 > s.length <-> t ≤ x := by
  have hk : (s.length - 1) / 2 < s.length := by
    rcases List.getElem?_eq_some_iff.mp median with ⟨h, _⟩
    exact h
  have hx : s[(s.length - 1) / 2] = x := by
    rcases List.getElem?_eq_some_iff.mp median with ⟨_, e⟩
    exact e
  constructor
  · intro many
    apply Nat.le_of_not_lt
    intro below
    have low : (s.take ((s.length - 1) / 2 + 1)).countP (fun m => decide (t ≤ m)) = 0 := by
      rw [List.countP_eq_zero]
      intro y mem
      rcases List.mem_iff_getElem.mp mem with ⟨i, hi, rfl⟩
      simp only [List.length_take] at hi
      simp only [List.getElem_take, decide_eq_true_eq, Nat.not_le]
      have : s[i] ≤ s[(s.length - 1) / 2] := sorted_le sorted (by omega) hk
      omega
    have high :
        (s.drop ((s.length - 1) / 2 + 1)).countP (fun m => decide (t ≤ m))
          <= s.length - ((s.length - 1) / 2 + 1) := by
      have := List.countP_le_length (p := fun m => decide (t ≤ m))
        (l := s.drop ((s.length - 1) / 2 + 1))
      simpa only [List.length_drop] using this
    have split := List.take_append_drop ((s.length - 1) / 2 + 1) s
    have total := congrArg (List.countP fun m => decide (t ≤ m)) split
    rw [List.countP_append, low] at total
    omega
  · intro le
    have high :
        (s.drop ((s.length - 1) / 2)).countP (fun m => decide (t ≤ m))
          = s.length - (s.length - 1) / 2 := by
      rw [List.countP_eq_length.mpr, List.length_drop]
      intro y mem
      rcases List.mem_iff_getElem.mp mem with ⟨i, hi, rfl⟩
      simp only [List.length_drop] at hi
      simp only [List.getElem_drop, decide_eq_true_eq]
      have : s[(s.length - 1) / 2] ≤ s[(s.length - 1) / 2 + i] :=
        sorted_le sorted (by omega) (by omega)
      omega
    have split := List.take_append_drop ((s.length - 1) / 2) s
    have total := congrArg (List.countP fun m => decide (t ≤ m)) split
    rw [List.countP_append, high] at total
    omega

/-- The median of the sorted match indexes, as `confirmedIdx` computes it. -/
theorem median_iff {ms : List Nat} {x : Nat}
    (median : (ms.mergeSort)[(ms.mergeSort.length - 1) / 2]? = some x) (t : Nat)
    : ms.countP (fun m => decide (t ≤ m)) * 2 > ms.length <-> t ≤ x := by
  have perm := List.mergeSort_perm ms (fun a b => decide (a ≤ b))
  have sorted : (ms.mergeSort).Pairwise (· ≤ ·) := by
    have := List.pairwise_mergeSort (le := fun a b : Nat => decide (a ≤ b))
      (fun a b c ab bc => by simp only [decide_eq_true_eq] at *; omega)
      (fun a b => by simp only [Bool.or_eq_true, decide_eq_true_eq]; omega) ms
    simpa only [decide_eq_true_eq] using this
  rw [← perm.countP_eq, ← perm.length_eq]
  exact sorted_median_iff sorted median t

/-! ## The loop of `highest_committable_idx` -/

open Consensus.TraceValidation.Exec (State Config)

section Agreement

variable (v : State) (L : Nat) (Q : Config -> Nat -> Prop)

/-- Every configuration of `K` that `t` reaches has a majority at `t`. -/
def AllReach (K : List Config) (t : Nat) : Prop :=
  forall c, c ∈ K -> c.idx <= t -> Q c t

/-- Some configuration of `K` is at or before `t`, and each such has a majority at `t`. -/
def Acc (K : List Config) (t : Nat) : Prop :=
  (exists c, c ∈ K /\ c.idx <= t) /\ AllReach Q K t

variable {v L Q}

theorem agreementGo_go
    : forall (K : List Config) (l : Nat) (agr r : Option Nat) (h0 : Nat)
              (A : Nat -> Prop),
        (forall c,
          c ∈ K
          -> forall x,
              Exec.confirmedIdx v c = .ok x -> forall t, t <= L -> (Q c t <-> t <= x))
        -> K.Pairwise (fun a b => a.idx < b.idx)
        -> (forall c, c ∈ K -> 0 < c.idx)
        -> Exec.agreementGo v (some l) K agr = .ok r
        -> agr
            = some
                (match K.head? with
                  | some n => min l (n.idx - 1)
                  | none => l)
        -> (forall t, t <= L -> (A t <-> h0 <= t /\ t <= l))
        -> forall t,
            t <= L
            -> (A t /\ AllReach Q K t <-> exists a, r = some a /\ h0 <= t /\ t <= a)
  | [], l, agr, r, h0, A, _, _, _, run, hagr, hA, t, tL => by
      simp only [Exec.agreementGo, Except.ok.injEq] at run
      subst run
      subst hagr
      simp only [List.head?_nil, Option.some.injEq, exists_eq_left']
      rw [hA t tL]
      simp [AllReach]
  | c :: rest, l, agr, r, h0, A, hQ, sorted, pos, run, hagr, hA, t, tL => by
      simp only [Exec.agreementGo] at run
      cases hx : Exec.confirmedIdx v c with
      | error e => simp [hx, bind, Except.bind] at run
      | ok x =>
        simp only [hx, bind, Except.bind, pure, Except.pure] at run
        have hc := hQ c List.mem_cons_self x hx
        have restAbove : forall c', c' ∈ rest -> c.idx < c'.idx := by
          intro c' mem
          exact List.rel_of_pairwise_cons sorted mem
        by_cases br : min l x < c.idx
        · simp only [br, ite_true, Except.ok.injEq] at run
          subst run
          subst hagr
          simp only [List.head?_cons, Option.some.injEq, exists_eq_left']
          have cpos := pos c List.mem_cons_self
          constructor
          · rintro ⟨at_, all⟩
            rw [hA t tL] at at_
            refine ⟨at_.1, ?_⟩
            have : t < c.idx := by
              apply Nat.lt_of_not_le
              intro reach
              have := (hc t tL).mp (all c List.mem_cons_self reach)
              omega
            omega
          · rintro ⟨h0t, tle⟩
            refine ⟨(hA t tL).mpr ⟨h0t, by omega⟩, ?_⟩
            intro c' mem reach
            rcases List.mem_cons.mp mem with rfl | mem
            · omega
            · have := restAbove c' mem
              omega
        · simp only [br, ite_false] at run
          have ih :=
            agreementGo_go rest (min l x) _ r h0
              (fun t => A t /\ (c.idx <= t -> Q c t))
              (fun c' mem => hQ c' (List.mem_cons_of_mem _ mem)) (List.Pairwise.of_cons sorted)
              (fun c' mem => pos c' (List.mem_cons_of_mem _ mem)) run rfl
              (by
                intro t tL
                rw [hA t tL]
                constructor
                · rintro ⟨⟨h0t, tl⟩, q⟩
                  refine ⟨h0t, Nat.le_min.mpr ⟨tl, ?_⟩⟩
                  by_cases reach : c.idx <= t
                  · exact (hc t tL).mp (q reach)
                  · omega
                · rintro ⟨h0t, tle⟩
                  have := Nat.le_min.mp tle
                  exact ⟨⟨h0t, this.1⟩, fun _ => (hc t tL).mpr this.2⟩)
              t tL
          rw [← ih]
          simp only [AllReach, List.mem_cons, forall_eq_or_imp]
          constructor
          · rintro ⟨at_, q, all⟩
            exact ⟨⟨at_, q⟩, all⟩
          · rintro ⟨⟨at_, q⟩, all⟩
            exact ⟨at_, q, all⟩

/--
`highest_committable_idx`'s loop over sorted configurations: an index within the ledger is
reached by a majority of every configuration it reaches, and reaches one, exactly when it
is at most the loop's result, and at least the first configuration's index.
-/
theorem agreementGo_spec {K : List Config}
    (hQ
      : forall c,
          c ∈ K
          -> forall x,
              Exec.confirmedIdx v c = .ok x -> forall t, t <= L -> (Q c t <-> t <= x))
    {r : Option Nat} (sorted : K.Pairwise (fun a b => a.idx < b.idx))
    (pos : forall c, c ∈ K -> 0 < c.idx) (run : Exec.agreementGo v none K none = .ok r)
    : forall t,
        t <= L
        -> (Acc Q K t
            <-> exists a c, r = some a /\ K.head? = some c /\ c.idx <= t /\ t <= a) := by
  intro t tL
  cases K with
  | nil =>
      simp only [Exec.agreementGo, Except.ok.injEq] at run
      subst run
      simp [Acc]
  | cons c rest =>
      simp only [Exec.agreementGo] at run
      cases hx : Exec.confirmedIdx v c with
      | error e => simp [hx, bind, Except.bind] at run
      | ok x =>
          simp only [hx, bind, Except.bind, pure, Except.pure] at run
          have hc := hQ c List.mem_cons_self x hx
          have restAbove : forall c', c' ∈ rest -> c.idx < c'.idx := by
            intro c' mem
            exact List.rel_of_pairwise_cons sorted mem
          have accIff : Acc Q (c :: rest) t <-> (c.idx <= t /\ (c.idx <= t -> Q c t))
              /\ AllReach Q rest t := by
            simp only [Acc, AllReach, List.mem_cons, exists_eq_or_imp, forall_eq_or_imp]
            constructor
            · rintro ⟨ex, q, all⟩
              refine ⟨⟨?_, q⟩, all⟩
              rcases ex with reach | ⟨c', mem, reach⟩
              · exact reach
              · have := restAbove c' mem
                omega
            · rintro ⟨⟨reach, q⟩, all⟩
              exact ⟨Or.inl reach, q, all⟩
          simp only [List.head?_cons, Option.some.injEq, exists_and_left, exists_eq_left']
          by_cases br : x < c.idx
          · simp only [br, ite_true, Except.ok.injEq] at run
            subst run
            simp only [reduceCtorEq, false_and, exists_false, iff_false]
            rw [accIff]
            rintro ⟨⟨reach, q⟩, _⟩
            have := (hc t tL).mp (q reach)
            omega
          · simp only [br, ite_false] at run
            rw [accIff]
            have := agreementGo_go rest x _ r c.idx
              (fun t => c.idx <= t /\ (c.idx <= t -> Q c t))
              (fun c' mem => hQ c' (List.mem_cons_of_mem _ mem)) (List.Pairwise.of_cons sorted)
              (fun c' mem => pos c' (List.mem_cons_of_mem _ mem)) run rfl
              (by
                intro t tL
                constructor
                · rintro ⟨reach, q⟩
                  exact ⟨reach, (hc t tL).mp (q reach)⟩
                · rintro ⟨reach, le⟩
                  exact ⟨reach, fun _ => (hc t tL).mpr le⟩)
              t tL
            rw [this]

end Agreement

/-! ## The clean commit fold -/

section Fold

/-- Commit indexes reachable from `ci` by steps `y` to `s` with `P y s`, within `L`. -/
inductive Reach (P : Nat -> Nat -> Prop) (ci L : Nat) : Nat -> Prop
  | base : Reach P ci L ci
  | step {y s : Nat} : Reach P ci L y -> y < s -> s <= L -> P y s -> Reach P ci L s

/-- No step leaves `c`. -/
def Final (P : Nat -> Nat -> Prop) (L c : Nat) : Prop :=
  forall s, c < s -> s <= L -> Not (P c s)

theorem Reach.ge {P : Nat -> Nat -> Prop} {ci L c : Nat} (h : Reach P ci L c)
    : ci <= c := by
  induction h with
  | base => exact Nat.le_refl _
  | step _ ys _ _ ih => omega

theorem Reach.le {P : Nat -> Nat -> Prop} {ci L c : Nat} (ciL : ci <= L)
    (h : Reach P ci L c)
    : c <= L := by
  cases h with
  | base => exact ciL
  | step _ _ sL _ => exact sL

/--
When a step from `y` to `s` is also a step from any `c` between them, a reachable final
index is unique.
-/
theorem reach_final_unique {P : Nat -> Nat -> Prop} {ci L : Nat}
    (mono : forall y c s, y <= c -> c < s -> P y s -> P c s) {c1 c2 : Nat}
    (r1 : Reach P ci L c1) (f1 : Final P L c1) (r2 : Reach P ci L c2) (f2 : Final P L c2)
    : c1 = c2 := by
  have below : forall {a b}, Reach P ci L a -> Final P L a -> Reach P ci L b -> Not (a < b) := by
    intro a b ra fa rb
    induction rb with
    | base =>
        have := ra.ge
        omega
    | @step y s _ _ sL p ih =>
        intro lt
        by_cases ya : y <= a
        · exact fa s lt sL (mono y a s ya lt p)
        · exact ih (by omega)
  have := below r1 f1 r2
  have := below r2 f2 r1
  omega

theorem foldl_reach {P : Nat -> Nat -> Prop} {ci L : Nat} (f : Nat -> Nat -> Nat)
    (hf
      : forall c s, (s > c /\ P c s -> f c s = s) /\ (Not (s > c /\ P c s) -> f c s = c))
    : forall (n k c : Nat),
        k + n <= L + 1
        -> Reach P ci L c
        -> (forall s, c < s -> s < k -> Not (P c s))
        -> Reach P ci L ((List.range' k n).foldl f c)
            /\ forall s,
                (List.range' k n).foldl f c < s
                -> s < k + n
                -> Not (P ((List.range' k n).foldl f c) s)
  | 0, k, c, _, r, quiet => by simpa using And.intro r quiet
  | n + 1, k, c, bound, r, quiet => by
      rw [List.range'_succ, List.foldl_cons]
      have ih := foldl_reach (P := P) (ci := ci) (L := L) f hf n (k + 1) (f c k) (by omega)
        (by
          by_cases go : k > c /\ P c k
          · rw [(hf c k).1 go]
            exact Reach.step r go.1 (by omega) go.2
          · rw [(hf c k).2 go]
            exact r)
        (by
          intro s lt sk
          by_cases go : k > c /\ P c k
          · rw [(hf c k).1 go] at lt ⊢
            omega
          · rw [(hf c k).2 go] at lt ⊢
            by_cases sk' : s < k
            · exact quiet s lt sk'
            · have : s = k := by omega
              subst this
              exact fun p => go ⟨lt, p⟩)
      exact ⟨ih.1, fun s lt sk => ih.2 s lt (by omega)⟩

end Fold

/-! ## Index-sorted lists -/

/-- In an index-sorted list, the positions within a bound are a prefix. -/
theorem sorted_filter_prefix {α : Type} (idx : α -> Nat)
    : forall {l : List α},
        l.Pairwise (fun a b => idx a < idx b)
        -> forall (c i : Nat) (hi : i < l.length),
            idx l[i] <= c <-> i < (l.filter fun a => decide (idx a <= c)).length
  | [], _, _, _, hi => absurd hi (Nat.not_lt_zero _)
  | x :: t, sorted, c, i, hi => by
      have above : forall y, y ∈ t -> idx x < idx y := fun y mem => List.rel_of_pairwise_cons sorted mem
      by_cases xc : idx x <= c
      · rw [List.filter_cons_of_pos (by simpa using xc), List.length_cons]
        cases i with
        | zero => simpa using xc
        | succ j =>
            simp only [List.getElem_cons_succ]
            rw [sorted_filter_prefix idx (List.Pairwise.of_cons sorted) c j (by simpa using hi)]
            omega
      · rw [List.filter_cons_of_neg (by simpa using xc)]
        have none : (t.filter fun a => decide (idx a <= c)) = [] := by
          apply List.filter_eq_nil_iff.mpr
          intro y mem
          have := above y mem
          simp only [decide_eq_true_eq]
          omega
        rw [none]
        simp only [List.length_nil, Nat.not_lt_zero, iff_false]
        cases i with
        | zero => simpa using xc
        | succ j =>
            simp only [List.getElem_cons_succ]
            have := above _ (List.getElem_mem (l := t) (n := j) (by simpa using hi))
            omega

/-! ## The clean step and its monotonicity -/

open Consensus.Model.Node

/-- A step of the clean `highestCommittableIndex` fold from commit index `c` to `s`. -/
def cleanP (state : NodeState) (self : NodeID) (c s : Nat) : Prop :=
  isSignatureAt state.log s = true
  /\ termAt state.log s = state.currentTerm
  /\ hasQuorum
      ((activeConfigurations state.log c).filter
        fun configuration => configuration.index <= s)
      (state.activeMembers.filter fun node => node = self \/ state.matchIndex node >= s)

theorem highestCommittableIndex_reach (state : NodeState) (self : NodeID)
    : Reach (cleanP state self) state.commitIndex state.log.length
        (highestCommittableIndex state self)
      /\ Final (cleanP state self) state.log.length
          (highestCommittableIndex state self) := by
  unfold highestCommittableIndex
  dsimp only
  rw [List.range_eq_range']
  refine (fun this => ⟨this.1, fun s lt sL => this.2 s lt (by omega)⟩)
    (foldl_reach
      (P := cleanP state self)
      (ci := state.commitIndex)
      (L := state.log.length)
      _ ?_
      (state.log.length + 1)
      0 state.commitIndex
      (by omega)
      .base
      (by intro s _ lt; omega))
  intro c s
  constructor
  · intro h
    unfold cleanP at h
    split
    · rfl
    · contradiction
  · intro h
    unfold cleanP at h
    split
    · contradiction
    · rfl

theorem configurationHistory_sorted (log : List Entry)
    : (configurationHistory log).Pairwise fun a b => a.index < b.index := by
  have zipSorted : forall (l : List Entry) (start : Nat),
      (l.zipIdx start).Pairwise fun a b => a.2 < b.2 := by
    intro l
    induction l with
    | nil => simp
    | cons head tail ih =>
        intro start
        rw [List.zipIdx_cons, List.pairwise_cons]
        exact ⟨fun pair member => (List.mem_zipIdx member).1, ih (start + 1)⟩
  unfold configurationHistory
  refine List.Pairwise.filterMap _ (fun a b lt x xa y yb => ?_) (zipSorted log 1)
  obtain ⟨_, _, rfl⟩ := Option.map_eq_some_iff.mp xa
  obtain ⟨_, _, rfl⟩ := Option.map_eq_some_iff.mp yb
  exact lt

theorem activeConfigurations_mono (log : List Entry) {y c : Nat} (yc : y <= c)
    : (forall x, x ∈ activeConfigurations log c -> x ∈ activeConfigurations log y)
      /\ forall s,
          c <= s
          -> (exists x, x ∈ activeConfigurations log y /\ x.index <= s)
          -> exists x, x ∈ activeConfigurations log c /\ x.index <= s := by
  have eq : forall c, activeConfigurations log c
      = (configurationHistory log).drop
          (((configurationHistory log).filter fun x => decide (x.index <= c)).length - 1) :=
    fun _ => rfl
  rw [eq c, eq y]
  have sorted := configurationHistory_sorted log
  generalize configurationHistory log = H at *
  have ky : (H.filter fun x => decide (x.index <= y)).length
      <= (H.filter fun x => decide (x.index <= c)).length := by
    simp only [← List.countP_eq_length_filter]
    apply List.countP_mono_left
    intro x _ h
    simp only [decide_eq_true_eq] at h ⊢
    omega
  refine ⟨fun x mem => ?_, fun s cs ex => ?_⟩
  · have : H.drop ((H.filter fun x => decide (x.index <= c)).length - 1)
        = (H.drop ((H.filter fun x => decide (x.index <= y)).length - 1)).drop
            ((H.filter fun x => decide (x.index <= c)).length - 1
              - ((H.filter fun x => decide (x.index <= y)).length - 1)) := by
      rw [List.drop_drop]
      congr 1
      omega
    exact List.mem_of_mem_drop (this ▸ mem)
  · by_cases kc : (H.filter fun x => decide (x.index <= c)).length = 0
    · have : (H.filter fun x => decide (x.index <= y)).length = 0 := by omega
      rw [kc]
      rw [this] at ex
      exact ex
    · have lt : (H.filter fun x => decide (x.index <= c)).length - 1 < H.length := by
        have := List.length_filter_le (fun x => decide (x.index <= c)) H
        omega
      refine ⟨H[(H.filter fun x => decide (x.index <= c)).length - 1], ?_, ?_⟩
      · exact List.mem_iff_getElem.mpr ⟨0, by simp only [List.length_drop]; omega, by simp⟩
      · have := (sorted_filter_prefix Configuration.index sorted c _ lt).mpr (by omega)
        omega

theorem cleanP_mono (state : NodeState) (self : NodeID)
    : forall y c s,
        y <= c -> c < s -> cleanP state self y s -> cleanP state self c s := by
  intro y c s yc cs ⟨sig, term, quorum⟩
  refine ⟨sig, term, ?_⟩
  obtain ⟨sub, ex⟩ := activeConfigurations_mono state.log yc
  unfold hasQuorum at quorum ⊢
  obtain ⟨nonempty, all⟩ := quorum
  obtain ⟨x, mem⟩ := List.exists_mem_of_ne_nil _ nonempty
  rw [List.mem_filter] at mem
  obtain ⟨x', mem', le'⟩ := ex s (by omega) ⟨x, mem.1, by simpa using mem.2⟩
  refine ⟨List.ne_nil_of_mem (List.mem_filter.mpr ⟨mem', by simpa using le'⟩), ?_⟩
  rw [List.all_eq_true] at all ⊢
  intro z memz
  rw [List.mem_filter] at memz
  exact all z (List.mem_filter.mpr ⟨sub z memz.1, memz.2⟩)

/-! ## The declared ledger: entries, terms and committable indexes -/

section Declared

open Consensus.TraceValidation (Names abs absEntry signaturesIn)

/-- The declared ledger has a signature at one-based index `s`. -/
abbrev SigAt (v : State) (s : Nat) : Prop := v.ledger[s - 1]?.any (·.sig) = true

theorem abs_log_length {names : Names} {v : State} (size : v.ledger.size = v.lastIdx)
    : (abs names v).log.length = v.lastIdx := by
  simp [abs, size]

theorem abs_entryAt {names : Names} {v : State} (size : v.ledger.size = v.lastIdx)
    {s : Nat} (s1 : 1 <= s) (sL : s <= v.lastIdx)
    : exists e,
        v.ledger[s - 1]? = some e
        /\ entryAt? (abs names v).log s = some (absEntry names e) := by
  have lt : s - 1 < v.ledger.size := by omega
  refine ⟨v.ledger[s - 1], by simp [lt], ?_⟩
  have ne : s ≠ 0 := by omega
  simp [entryAt?, abs, ne, show s - 1 < v.lastIdx by omega, lt]

theorem abs_isSignatureAt {names : Names} {v : State} (size : v.ledger.size = v.lastIdx)
    {s : Nat} (s1 : 1 <= s) (sL : s <= v.lastIdx)
    : isSignatureAt (abs names v).log s = true <-> SigAt v s := by
  obtain ⟨e, he, entry⟩ := abs_entryAt (names := names) size s1 sL
  unfold isSignatureAt SigAt
  rw [entry, he]
  cases hs : e.sig <;> simp [absEntry, hs, EntryContent.isSignature]

theorem abs_termAt {names : Names} {v : State} (size : v.ledger.size = v.lastIdx)
    {s : Nat} (s1 : 1 <= s) (sL : s <= v.lastIdx)
    : exists e, v.ledger[s - 1]? = some e /\ termAt (abs names v).log s = e.term := by
  obtain ⟨e, he, entry⟩ := abs_entryAt (names := names) size s1 sL
  refine ⟨e, he, ?_⟩
  unfold termAt
  rw [entry]
  simp [absEntry]

theorem isSignatureAt_zero (log : List Entry) : isSignatureAt log 0 = false := by
  simp [isSignatureAt, entryAt?]

theorem viewAt_mono (v : State) {i j : Nat} (ij : i <= j) : v.viewAt i <= v.viewAt j := by
  unfold State.viewAt
  simp only [← List.countP_eq_length_filter]
  apply List.countP_mono_left
  intro x _ h
  simp only [decide_eq_true_eq] at h ⊢
  omega

theorem viewAt_le_size (v : State) (i : Nat) : v.viewAt i <= v.views.size := by
  unfold State.viewAt
  have := List.length_filter_le (fun x => decide (x <= i)) v.views.toList
  simpa using this

theorem sorted_getLast_max {l : List Nat} (sorted : l.Pairwise (· < ·)) {x : Nat}
    (last : l.getLast? = some x)
    : forall y, y ∈ l -> y <= x := by
  obtain ⟨ys, rfl⟩ := List.getLast?_eq_some_iff.mp last
  intro y mem
  rcases List.mem_append.mp mem with mem | mem
  · have := (List.pairwise_append.mp sorted).2.2 y mem x (List.mem_singleton_self _)
    omega
  · simp only [List.mem_singleton] at mem
    omega

theorem highestCommittableLe_none {v : State}
    (committable : v.committable = signaturesIn v v.commitIdx v.lastIdx) {a : Nat}
    (none_ : v.highestCommittableLe a = none)
    : forall s, v.commitIdx < s -> s <= v.lastIdx -> s <= a -> Not (SigAt v s) := by
  intro s lo hi sa sig
  unfold State.highestCommittableLe at none_
  rw [committable, List.getLast?_eq_none_iff] at none_
  have : s ∈ ((signaturesIn v v.commitIdx v.lastIdx).filter fun i => decide (i <= a)) := by
    simp only [signaturesIn, List.mem_filter, List.mem_range'_1, decide_eq_true_eq]
    exact ⟨⟨⟨by omega, by omega⟩, sig⟩, sa⟩
  rw [none_] at this
  cases this

theorem highestCommittableLe_some {v : State}
    (committable : v.committable = signaturesIn v v.commitIdx v.lastIdx) {a nc : Nat}
    (some_ : v.highestCommittableLe a = some nc)
    : v.commitIdx < nc
      /\ nc <= v.lastIdx
      /\ nc <= a
      /\ SigAt v nc
      /\ forall s, nc < s -> s <= v.lastIdx -> s <= a -> Not (SigAt v s) := by
  unfold State.highestCommittableLe at some_
  rw [committable] at some_
  have sorted : ((signaturesIn v v.commitIdx v.lastIdx).filter fun i => decide (i <= a)).Pairwise
      (· < ·) := by
    unfold signaturesIn
    exact ((List.pairwise_lt_range' (s := v.commitIdx + 1) (n := v.lastIdx - v.commitIdx)).filter _).filter _
  have mem : nc ∈ ((signaturesIn v v.commitIdx v.lastIdx).filter fun i => decide (i <= a)) := by
    obtain ⟨ys, eq⟩ := List.getLast?_eq_some_iff.mp some_
    rw [eq]
    exact List.mem_append_right _ (List.mem_singleton_self _)
  have max := sorted_getLast_max sorted some_
  simp only [signaturesIn, List.mem_filter, List.mem_range'_1, decide_eq_true_eq] at mem
  refine ⟨by omega, by omega, mem.2, mem.1.2, fun s lo hi sa sig => ?_⟩
  have := max s (by
    simp only [signaturesIn, List.mem_filter, List.mem_range'_1, decide_eq_true_eq]
    exact ⟨⟨⟨by omega, by omega⟩, sig⟩, sa⟩)
  omega

end Declared

/-! ## Declared configurations and the clean active configurations -/

section Configs

open Consensus.TraceValidation (Names abs)

/-- The clean configuration a declared configuration stands for. -/
def absConfig (names : Names) (c : Config) : Configuration :=
  { index := c.idx, nodes := names.set (c.nodes.map Prod.fst) }

/--
The position in `D` that `update_commit`'s `first` holds once the commit index is `c`: the
number of configurations after the first that `c` reaches.
-/
def firstAt (D : List Config) (c : Nat) : Nat :=
  ((D.drop 1).filter fun x => decide (x.idx <= c)).length

theorem filter_drop_length {α : Type} (idx : α -> Nat)
    : forall {l : List α},
        l.Pairwise (fun a b => idx a < idx b)
        -> forall (m c : Nat),
            ((l.drop m).filter fun a => decide (idx a <= c)).length
            = (l.filter fun a => decide (idx a <= c)).length - m
  | [], _, m, c => by simp
  | x :: t, _, 0, c => by simp
  | x :: t, sorted, m + 1, c => by
      rw [List.drop_succ_cons, filter_drop_length idx (List.Pairwise.of_cons sorted) m c]
      by_cases xc : idx x <= c
      · rw [List.filter_cons_of_pos (by simpa using xc), List.length_cons]
        omega
      · rw [List.filter_cons_of_neg (by simpa using xc)]
        have : (t.filter fun a => decide (idx a <= c)) = [] :=
          List.filter_eq_nil_iff.mpr fun y mem => by
            have := List.rel_of_pairwise_cons sorted mem
            simp only [decide_eq_true_eq]
            omega
        rw [this]
        simp

theorem finset_eq_of_sort {s t : CCF.Finset NodeID} (h : s.sort = t.sort) : s = t := by
  cases s
  cases t
  simp only [CCF.Finset.sort] at h
  subst h
  rfl

theorem configs_of_map (names : Names)
    : forall (D : List Config) (A : List Configuration),
        D.map (fun c => (c.idx, (names.set (c.nodes.map Prod.fst)).sort))
          = A.map (fun c => (c.index, c.nodes.sort))
        -> A = D.map (absConfig names)
  | [], [], _ => rfl
  | [], _ :: _, h => by simp at h
  | _ :: _, [], h => by simp at h
  | x :: D, a :: A, h => by
      simp only [List.map_cons, List.cons.injEq, Prod.mk.injEq] at h
      obtain ⟨⟨hi, hn⟩, rest⟩ := h
      rw [configs_of_map names D A rest]
      congr 1
      cases a
      simp only [absConfig] at hi hn ⊢
      rw [hi, finset_eq_of_sort hn]

theorem configurationHistory_pos {log : List Entry} {x : Configuration}
    (mem : x ∈ configurationHistory log)
    : 0 < x.index := by
  unfold configurationHistory at mem
  obtain ⟨⟨e, i⟩, zmem, hx⟩ := List.mem_filterMap.mp mem
  obtain ⟨_, _, rfl⟩ := Option.map_eq_some_iff.mp hx
  have := (List.mem_zipIdx zmem).1
  simp only
  omega

theorem active_sorted (log : List Entry) (c : Nat)
    : (activeConfigurations log c).Pairwise fun a b => a.index < b.index :=
  (configurationHistory_sorted log).sublist (List.drop_sublist _ _)

theorem active_pos {log : List Entry} {c : Nat} {x : Configuration}
    (mem : x ∈ activeConfigurations log c)
    : 0 < x.index :=
  configurationHistory_pos (List.mem_of_mem_drop mem)

theorem active_eq_drop (names : Names) (log : List Entry) {ci : Nat} {D : List Config}
    (hD : activeConfigurations log ci = D.map (absConfig names)) {c : Nat} (cic : ci <= c)
    : activeConfigurations log c = (D.drop (firstAt D c)).map (absConfig names) := by
  have eq : forall c, activeConfigurations log c
      = (configurationHistory log).drop
          (((configurationHistory log).filter fun x => decide (x.index <= c)).length - 1) :=
    fun _ => rfl
  have g : firstAt D c
      = (((activeConfigurations log ci).drop 1).filter fun x => decide (x.index <= c)).length := by
    rw [hD]
    unfold firstAt
    rw [← List.map_drop, List.filter_map, List.length_map]
    rfl
  rw [List.map_drop, ← hD, g, eq c, eq ci]
  have sorted := configurationHistory_sorted log
  generalize configurationHistory log = H at *
  simp only [List.drop_drop]
  rw [filter_drop_length Configuration.index sorted]
  have mono : (H.filter fun x => decide (x.index <= ci)).length
      <= (H.filter fun x => decide (x.index <= c)).length := by
    simp only [← List.countP_eq_length_filter]
    apply List.countP_mono_left
    intro x _ h
    simp only [decide_eq_true_eq] at h ⊢
    omega
  congr 1
  omega

theorem firstAt_self (names : Names) (log : List Entry) {ci : Nat} {D : List Config}
    (hD : activeConfigurations log ci = D.map (absConfig names))
    : firstAt D ci = 0 := by
  have := active_eq_drop names log hD (Nat.le_refl ci)
  have g : firstAt D ci
      = (((D.map (absConfig names)).drop 1).filter fun x => decide (x.index <= ci)).length := by
    unfold firstAt
    rw [← List.map_drop, List.filter_map, List.length_map]
    rfl
  rw [g, ← hD]
  unfold activeConfigurations
  dsimp only
  have sorted := configurationHistory_sorted log
  generalize configurationHistory log = H at *
  rw [List.drop_drop, filter_drop_length Configuration.index sorted]
  omega

theorem declared_sorted {names : Names} {log : List Entry} {ci : Nat} {D : List Config}
    (hD : activeConfigurations log ci = D.map (absConfig names))
    : D.Pairwise fun a b => a.idx < b.idx := by
  have := active_sorted log ci
  rw [hD, List.pairwise_map] at this
  exact this

theorem declared_pos {names : Names} {log : List Entry} {ci : Nat} {D : List Config}
    (hD : activeConfigurations log ci = D.map (absConfig names)) {x : Config}
    (mem : x ∈ D)
    : 0 < x.idx := by
  have := active_pos (log := log) (c := ci) (x := absConfig names x)
    (by rw [hD]; exact List.mem_map_of_mem mem)
  simpa [absConfig] using this

theorem step_iff {D : List Config} (sorted : D.Pairwise fun a b => a.idx < b.idx)
    (i j : Nat)
    : (D[j + 1]?.any fun x => decide (x.idx <= i)) = true <-> j < firstAt D i := by
  unfold firstAt
  by_cases hj : j < (D.drop 1).length
  · have := sorted_filter_prefix Config.idx (sorted.sublist (List.drop_sublist 1 D)) i j hj
    rw [← this]
    have e : D[j + 1]? = (D.drop 1)[j]? := by
      rw [List.getElem?_drop, Nat.add_comm]
    rw [List.getElem?_eq_getElem hj] at e
    rw [e]
    simp
  · have none_ : D[j + 1]? = none := by
      apply List.getElem?_eq_none
      simp only [List.length_drop] at hj
      omega
    rw [none_]
    have := List.length_filter_le (fun x : Config => decide (x.idx <= i)) (D.drop 1)
    simp only [Option.any_none, Bool.false_eq_true, false_iff]
    omega

theorem advanceFirst_eq {D : List Config} (sorted : D.Pairwise fun a b => a.idx < b.idx)
    (i : Nat)
    : forall fuel first,
        first <= firstAt D i
        -> firstAt D i - first <= fuel
        -> Exec.advanceFirst D i first fuel = firstAt D i
  | 0, first, le, fuel => by
      simp only [Exec.advanceFirst]
      omega
  | fuel + 1, first, le, enough => by
      simp only [Exec.advanceFirst]
      split
      · rename_i go
        have := (step_iff sorted i first).mp go
        exact advanceFirst_eq sorted i fuel (first + 1) (by omega) (by omega)
      · rename_i go
        have := mt (step_iff sorted i first).mpr go
        omega

theorem firstAt_le_length (D : List Config) (c : Nat) : firstAt D c <= D.length := by
  unfold firstAt
  have := List.length_filter_le (fun x : Config => decide (x.idx <= c)) (D.drop 1)
  simp only [List.length_drop] at this
  omega

theorem mem_configurationMembers {cs : List Configuration} {x : Configuration}
    {n : NodeID} (mem : x ∈ cs) (member : n ∈ x.nodes)
    : n ∈ configurationMembers cs := by
  unfold configurationMembers
  have general : forall (cs : List Configuration) (acc : CCF.Finset NodeID),
      (n ∈ acc \/ exists x, x ∈ cs /\ n ∈ x.nodes)
      -> n ∈ cs.foldl (fun nodes configuration => nodes ∪ configuration.nodes) acc := by
    intro cs
    induction cs with
    | nil =>
        intro acc h
        rcases h with h | ⟨_, mem, _⟩
        · exact h
        · cases mem
    | cons y ys ih =>
        intro acc h
        apply ih
        rcases h with h | ⟨z, mem, inZ⟩
        · exact Or.inl (CCF.Finset.mem_union.mpr (Or.inl h))
        · rcases List.mem_cons.mp mem with rfl | mem
          · exact Or.inl (CCF.Finset.mem_union.mpr (Or.inr inZ))
          · exact Or.inr ⟨z, mem, inZ⟩
  exact general cs ∅ (Or.inr ⟨x, mem, member⟩)

/--
`E` is `D` except that its first configuration may sit at a later index, both at or below
`ci`: a joiner's snapshot configuration (`inv`'s `configurations`).
-/
def Shifted (ci : Nat) (D E : List Config) : Prop :=
  D = E
  \/ exists x y rest,
      D = x :: rest /\ E = y :: rest /\ x.nodes = y.nodes /\ x.idx <= y.idx /\ y.idx <= ci

/-- The clean active configurations after the first are above the commit index. -/
theorem active_tail_above (names : Names) (log : List Entry) {ci : Nat} {D : List Config}
    (hD : activeConfigurations log ci = D.map (absConfig names))
    : forall x, x ∈ D.drop 1 -> ci < x.idx := by
  have zero := firstAt_self names log hD
  unfold firstAt at zero
  intro x mem
  have := List.filter_eq_nil_iff.mp (List.eq_nil_of_length_eq_zero zero) x mem
  simp only [decide_eq_true_eq] at this
  omega

theorem shifted_sorted {names : Names} {log : List Entry} {ci : Nat} {D E : List Config}
    (hD : activeConfigurations log ci = D.map (absConfig names)) (sh : Shifted ci D E)
    : E.Pairwise fun a b => a.idx < b.idx := by
  have sorted := declared_sorted hD
  rcases sh with rfl | ⟨x, y, rest, rfl, rfl, _, _, yc⟩
  · exact sorted
  · have above := active_tail_above names log hD
    simp only [List.drop_succ_cons, List.drop_zero] at above
    refine List.pairwise_cons.mpr ⟨fun z mem => ?_, (List.pairwise_cons.mp sorted).2⟩
    have := above z mem
    omega

theorem shifted_pos {names : Names} {log : List Entry} {ci : Nat} {D E : List Config}
    (hD : activeConfigurations log ci = D.map (absConfig names)) (sh : Shifted ci D E)
    {x : Config} (mem : x ∈ E)
    : 0 < x.idx := by
  rcases sh with rfl | ⟨x', y, rest, rfl, rfl, _, xy, _⟩
  · exact declared_pos hD mem
  · rcases List.mem_cons.mp mem with rfl | mem
    · have := declared_pos hD List.mem_cons_self
      omega
    · exact declared_pos hD (List.mem_cons_of_mem _ mem)

theorem shifted_firstAt {ci : Nat} {D E : List Config} (sh : Shifted ci D E) (c : Nat)
    : firstAt E c = firstAt D c := by
  rcases sh with rfl | ⟨x, y, rest, rfl, rfl, _⟩
  · rfl
  · rfl

theorem shifted_mem {ci : Nat} {D E : List Config} (sh : Shifted ci D E) {y : Config}
    (mem : y ∈ E)
    : exists x, x ∈ D /\ x.nodes = y.nodes := by
  rcases sh with rfl | ⟨x, y', rest, rfl, rfl, nodes, _⟩
  · exact ⟨y, mem, rfl⟩
  · rcases List.mem_cons.mp mem with rfl | mem
    · exact ⟨x, List.mem_cons_self, nodes⟩
    · exact ⟨y, List.mem_cons_of_mem _ mem, rfl⟩

/-- Above `ci`, a shifted list of configurations has the same majorities. -/
theorem shifted_acc {ci : Nat} {D E : List Config} (sh : Shifted ci D E)
    {Q : Config -> Nat -> Prop} {t : Nat}
    (same : forall x y, x.nodes = y.nodes -> (Q x t <-> Q y t)) (above : ci < t) (k : Nat)
    : Acc Q (E.drop k) t <-> Acc Q (D.drop k) t := by
  rcases sh with rfl | ⟨x, y, rest, rfl, rfl, nodes, xy, yc⟩
  · exact Iff.rfl
  · cases k with
    | succ k => exact Iff.rfl
    | zero =>
        simp only [List.drop_zero, Acc, AllReach, List.mem_cons, exists_eq_or_imp,
          forall_eq_or_imp]
        have q := same x y nodes
        constructor
        · rintro ⟨_, qy, all⟩
          exact ⟨Or.inl (by omega), fun _ => q.mpr (qy (by omega)), all⟩
        · rintro ⟨_, qx, all⟩
          exact ⟨Or.inl (by omega), fun _ => q.mp (qx (by omega)), all⟩

end Configs

/-! ## Names, peers and the majority of one configuration -/

section Majority

open Consensus.TraceValidation (Names abs)

/-- An id that round-trips through the name table. -/
abbrev Named (names : Names) (id : Exec.NodeId) : Prop := names.name (names.id id) = id

theorem named_inj {names : Names} {x y : Exec.NodeId} (hx : Named names x)
    (hy : Named names y) (same : names.id x = names.id y)
    : x = y := by
  rw [← hx, ← hy, same]

theorem mapM_ok_nat {α : Type} {f : α -> Except String Nat}
    : forall {l : List α} {ms : List Nat},
        l.mapM f = .ok ms
        -> (forall a, a ∈ l -> exists b, f a = .ok b)
            /\ ms = l.map fun a => (f a).toOption.getD 0
  | [], ms, h => by
      simp only [List.mapM_nil, Pure.pure, Except.pure, Except.ok.injEq] at h
      subst h
      simp
  | a :: l, ms, h => by
      simp only [List.mapM_cons, Bind.bind, Except.bind, Pure.pure, Except.pure] at h
      cases fa : f a with
      | error e => simp [fa] at h
      | ok b =>
          rw [fa] at h
          cases fl : l.mapM f with
          | error e => simp [fl] at h
          | ok bs =>
              rw [fl] at h
              simp only [Except.ok.injEq] at h
              subst h
              obtain ⟨all, eq⟩ := mapM_ok_nat fl
              refine ⟨?_, ?_⟩
              · intro x mem
                rcases List.mem_cons.mp mem with rfl | mem
                · exact ⟨b, fa⟩
                · exact all x mem
              · simp [fa, eq, Except.toOption]

/-- The clean match index of a peer is its declared one. -/
theorem abs_matchIndex {names : Names} {v : State}
    (peersNamed : forall p, p ∈ v.allOtherNodes -> Named names p.1) {id : Exec.NodeId}
    (named : Named names id) {p : Exec.Peer} (found : v.peer? id = some p)
    : (abs names v).matchIndex (names.id id) = p.matchIdx := by
  simp only [abs]
  unfold State.peer? at found
  generalize v.allOtherNodes = l at peersNamed found
  induction l with
  | nil => simp at found
  | cons q l ih =>
      obtain ⟨k, pk⟩ := q
      by_cases same : id = k
      · subst same
        simp only [List.lookup_cons, beq_self_eq_true, Option.some.injEq] at found
        subst found
        simp
      · have ne : (names.id k == names.id id) = false := by
          simp only [beq_eq_false_iff_ne]
          intro eq
          exact same (named_inj named (peersNamed (k, pk) (by simp)) eq.symm)
        have ne' : (id == k) = false := by simpa using same
        simp only [List.lookup_cons, ne'] at found
        simp only [List.find?_cons, ne]
        exact ih (fun p mem => peersNamed p (List.mem_cons_of_mem _ mem)) found

/--
A configuration's clean majority at index `t` (the members that are the leader or have
matched `t`) exists exactly when `t` is at most its declared confirmed index.
-/
theorem majority_iff {names : Names} {v : State} (selfNamed : Named names v.nodeId)
    (peersNamed : forall p, p ∈ v.allOtherNodes -> Named names p.1) {x : Config}
    (membersNamed : forall a, a ∈ x.nodes -> Named names a.1)
    (distinct : (x.nodes.map Prod.fst).Nodup)
    (active : forall n, n ∈ (absConfig names x).nodes -> n ∈ (abs names v).activeMembers)
    {m : Nat} (confirmed : Exec.confirmedIdx v x = .ok m) {t : Nat} (tL : t <= v.lastIdx)
    : hasConfigurationMajority
        ((abs names v).activeMembers.filter
          fun n => n = names.id v.nodeId \/ (abs names v).matchIndex n >= t)
        (absConfig names x)
      <-> t <= m := by
  unfold Exec.confirmedIdx at confirmed
  cases hm : Exec.matchIdxs v x with
  | error e => simp [hm, Bind.bind, Except.bind] at confirmed
  | ok ms =>
      simp only [hm, Bind.bind, Except.bind] at confirmed
      split at confirmed
      · rename_i x' median
        simp only [Except.ok.injEq] at confirmed
        subst confirmed
        obtain ⟨all, eq⟩ := mapM_ok_nat hm
        have med := median_iff median t
        rw [← med, eq, List.countP_map, List.length_map]
        have nodupIds : ((x.nodes.map Prod.fst).map names.id).Nodup := by
          unfold List.Nodup
          rw [List.pairwise_map]
          refine List.Pairwise.imp_of_mem ?_ distinct
          intro a b ma mb ne same
          obtain ⟨a', ma', rfl⟩ := List.mem_map.mp ma
          obtain ⟨b', mb', rfl⟩ := List.mem_map.mp mb
          exact ne (named_inj (membersNamed a' ma') (membersNamed b' mb') same)
        unfold hasConfigurationMajority absConfig Names.set
        dsimp only
        rw [CCF.Finset.card_ofList_of_nodup nodupIds, List.length_map, List.length_map]
        let P : NodeID -> Bool :=
          fun n => decide (n = names.id v.nodeId \/ (abs names v).matchIndex n >= t)
        have card : (((abs names v).activeMembers.filter
              fun n => n = names.id v.nodeId \/ (abs names v).matchIndex n >= t)
              ∩ CCF.Finset.ofList ((x.nodes.map Prod.fst).map names.id)).card
            = (((x.nodes.map Prod.fst).map names.id).filter P).length := by
          apply CCF.Finset.length_eq_of_nodup_of_mem_iff
            (CCF.Finset.nodup_of_sorted (CCF.Finset.sorted _)) (List.Pairwise.filter _ nodupIds)
          intro n
          rw [← CCF.Finset.mem_def, CCF.Finset.mem_inter, CCF.Finset.mem_filter,
            CCF.Finset.mem_ofList, List.mem_filter]
          constructor
          · rintro ⟨⟨_, p⟩, mem⟩
            exact ⟨mem, by simpa [P] using p⟩
          · rintro ⟨mem, p⟩
            refine ⟨⟨active n ?_, by simpa [P] using p⟩, mem⟩
            simpa [absConfig, Names.set] using mem
        rw [card, ← List.countP_eq_length_filter, List.countP_map, List.countP_map]
        apply Iff.of_eq
        congr 2
        apply List.countP_congr
        intro a mem
        obtain ⟨b, fb⟩ := all a mem
        obtain ⟨id, tag⟩ := a
        simp only [Function.comp_apply, fb, Except.toOption, Option.getD_some, P,
          decide_eq_true_eq]
        simp only at fb
        split at fb
        · rename_i isSelf
          simp only [Except.ok.injEq] at fb
          subst fb
          simp only [beq_iff_eq] at isSelf
          subst isSelf
          simp only [true_or, true_iff]
          exact tL
        · rename_i notSelf
          simp only [beq_iff_eq] at notSelf
          have named := membersNamed (id, tag) mem
          have ne : names.id id ≠ names.id v.nodeId :=
            fun same => notSelf (named_inj named selfNamed same)
          split at fb
          · rename_i p found
            simp only [Except.ok.injEq] at fb
            subst fb
            rw [abs_matchIndex peersNamed named found]
            simp [ne]
          · cases fb
      · simp at confirmed

end Majority

/-! ## One round of `highest_committable_idx` against the clean fold -/

section Round

open Consensus.TraceValidation (Names abs signaturesIn)

/-- What `update_commit` needs of the declared state; `Hyps.ofInv` derives it from `inv`. -/
structure Hyps (names : Names) (v : State) : Prop where
  size : v.ledger.size = v.lastIdx
  commitLe : v.commitIdx <= v.lastIdx
  committable : v.committable = signaturesIn v v.commitIdx v.lastIdx
  terms
    : forall i,
        1 <= i -> i <= v.lastIdx -> v.ledger[i - 1]?.map (·.term) = some (v.viewAt i)
  viewsBounded : v.views.size <= v.currentView
  configs
    : 0 < v.lastIdx
      -> exists D,
          activeConfigurations (abs names v).log v.commitIdx = D.map (absConfig names)
          /\ Shifted v.commitIdx D v.configurations
  selfNamed : Named names v.nodeId
  peersNamed : forall p, p ∈ v.allOtherNodes -> Named names p.1
  membersNamed
    : forall x, x ∈ v.configurations -> forall a, a ∈ x.nodes -> Named names a.1
  distinct : forall x, x ∈ v.configurations -> (x.nodes.map Prod.fst).Nodup

/-- The clean majority of a declared configuration at index `t`. -/
def Qd (names : Names) (v : State) (x : Config) (t : Nat) : Prop :=
  hasConfigurationMajority
    ((abs names v).activeMembers.filter
      fun n => n = names.id v.nodeId \/ (abs names v).matchIndex n >= t)
    (absConfig names x)

variable {names : Names} {v : State}

theorem Hyps.hQ (h : Hyps names v) (L0 : 0 < v.lastIdx) (K : List Config)
    (sub : forall x, x ∈ K -> x ∈ v.configurations)
    : forall x,
        x ∈ K
        -> forall m,
            Exec.confirmedIdx v x = .ok m
            -> forall t, t <= v.lastIdx -> (Qd names v x t <-> t <= m) := by
  intro x mem m confirmed t tL
  have memD := sub x mem
  apply majority_iff h.selfNamed h.peersNamed (h.membersNamed x memD) (h.distinct x memD)
    _ confirmed tL
  intro n member
  show n ∈ configurationMembers (activeConfigurations (abs names v).log v.commitIdx)
  obtain ⟨D, hD, sh⟩ := h.configs L0
  obtain ⟨x', memD', nodes⟩ := shifted_mem sh memD
  rw [hD]
  exact mem_configurationMembers (List.mem_map_of_mem memD')
    (by simpa [absConfig, nodes] using member)

theorem Hyps.sorted (h : Hyps names v) (L0 : 0 < v.lastIdx)
    : v.configurations.Pairwise fun a b => a.idx < b.idx := by
  obtain ⟨_, hD, sh⟩ := h.configs L0
  exact shifted_sorted hD sh

theorem Hyps.pos (h : Hyps names v) (L0 : 0 < v.lastIdx) {x : Config}
    (mem : x ∈ v.configurations)
    : 0 < x.idx := by
  obtain ⟨_, hD, sh⟩ := h.configs L0
  exact shifted_pos hD sh mem

theorem Hyps.firstAt_self (h : Hyps names v) (L0 : 0 < v.lastIdx)
    : firstAt v.configurations v.commitIdx = 0 := by
  obtain ⟨_, hD, sh⟩ := h.configs L0
  rw [shifted_firstAt sh]
  exact ReplUpdateCommit.firstAt_self names _ hD

theorem cleanP_iff (h : Hyps names v) (L0 : 0 < v.lastIdx) {c s : Nat}
    (cic : v.commitIdx <= c) (cs : c < s) (sL : s <= v.lastIdx)
    : cleanP (abs names v) (names.id v.nodeId) c s
      <-> SigAt v s
          /\ v.viewAt s = v.currentView
          /\ Acc (Qd names v) (v.configurations.drop (firstAt v.configurations c)) s := by
  have s1 : 1 <= s := by omega
  obtain ⟨D, hD, sh⟩ := h.configs L0
  rw [shifted_firstAt sh, shifted_acc (Q := Qd names v) (t := s) sh
    (fun x y nodes => by simp [Qd, absConfig, hasConfigurationMajority, nodes]) (by omega)]
  unfold cleanP
  rw [abs_isSignatureAt h.size s1 sL]
  obtain ⟨e, he, ht⟩ := abs_termAt (names := names) h.size s1 sL
  rw [ht]
  have te := h.terms s s1 sL
  rw [he] at te
  simp only [Option.map_some, Option.some.injEq] at te
  rw [te]
  have cur : (abs names v).currentTerm = v.currentView := rfl
  rw [cur, active_eq_drop names _ hD cic]
  apply and_congr Iff.rfl
  apply and_congr Iff.rfl
  unfold hasQuorum Acc AllReach
  constructor
  · rintro ⟨ne, all⟩
    obtain ⟨y, memy⟩ := List.exists_mem_of_ne_nil _ ne
    simp only [List.mem_filter, List.mem_map, decide_eq_true_eq] at memy
    obtain ⟨⟨x, memx, rfl⟩, le⟩ := memy
    refine ⟨⟨x, memx, by simpa [absConfig] using le⟩, ?_⟩
    intro z memz le'
    rw [List.all_eq_true] at all
    have := all (absConfig names z)
      (List.mem_filter.mpr ⟨List.mem_map_of_mem memz, by simp [absConfig, le']⟩)
    simpa [Qd] using this
  · rintro ⟨⟨x, memx, le⟩, all⟩
    refine ⟨List.ne_nil_of_mem (a := absConfig names x)
      (List.mem_filter.mpr ⟨List.mem_map_of_mem memx, by simp [absConfig, le]⟩), ?_⟩
    rw [List.all_eq_true]
    intro y memy
    simp only [List.mem_filter, List.mem_map, decide_eq_true_eq] at memy
    obtain ⟨⟨z, memz, rfl⟩, le'⟩ := memy
    have := all z memz (by simpa [absConfig] using le')
    simpa [Qd] using this

theorem round (h : Hyps names v) (L0 : 0 < v.lastIdx) {c : Nat} (cic : v.commitIdx <= c)
    {r : Option Nat}
    (run : Exec.highestCommittableIdxOf v (firstAt v.configurations c) = .ok r)
    : (r = none -> Final (cleanP (abs names v) (names.id v.nodeId)) v.lastIdx c)
      /\ forall i,
          r = some i
          -> v.commitIdx < i
              /\ i <= v.lastIdx
              /\ (forall s,
                    i < s
                    -> c < s
                    -> s <= v.lastIdx
                    -> Not (cleanP (abs names v) (names.id v.nodeId) c s))
              /\ (c < i -> cleanP (abs names v) (names.id v.nodeId) c i) := by
  have sortedK := (h.sorted L0).sublist
    (List.drop_sublist (firstAt v.configurations c) v.configurations)
  have subK : forall x, x ∈ v.configurations.drop (firstAt v.configurations c)
      -> x ∈ v.configurations := fun x m => List.mem_of_mem_drop m
  have stepOf : forall s, c < s -> s <= v.lastIdx
      -> cleanP (abs names v) (names.id v.nodeId) c s
      -> SigAt v s /\ v.viewAt s = v.currentView
        /\ Acc (Qd names v) (v.configurations.drop (firstAt v.configurations c)) s :=
    fun s cs sL p => (cleanP_iff h L0 cic cs sL).mp p
  have stepTo : forall s, c < s -> s <= v.lastIdx
      -> SigAt v s /\ v.viewAt s = v.currentView
        /\ Acc (Qd names v) (v.configurations.drop (firstAt v.configurations c)) s
      -> cleanP (abs names v) (names.id v.nodeId) c s :=
    fun s cs sL p => (cleanP_iff h L0 cic cs sL).mpr p
  unfold Exec.highestCommittableIdxOf at run
  generalize v.configurations.drop (firstAt v.configurations c) = K
    at run sortedK subK stepOf stepTo
  cases hag : Exec.agreementGo v none K none with
  | error e => simp [hag, bind, Except.bind] at run
  | ok r' =>
      have spec := agreementGo_spec (h.hQ L0 K subK) sortedK
        (fun x m => h.pos L0 (subK x m)) hag
      simp only [hag, bind, Except.bind] at run
      have bound : forall s, c < s -> s <= v.lastIdx
          -> cleanP (abs names v) (names.id v.nodeId) c s
          -> SigAt v s /\ v.viewAt s = v.currentView
            /\ exists a c0, r' = some a /\ K.head? = some c0 /\ c0.idx <= s /\ s <= a := by
        intro s cs sL p
        obtain ⟨sig, view, acc⟩ := stepOf s cs sL p
        exact ⟨sig, view, (spec s sL).mp acc⟩
      cases r' with
      | none =>
          simp only [pure, Except.pure, Except.ok.injEq] at run
          subst run
          refine ⟨fun _ s cs sL p => ?_, fun i no => by cases no⟩
          obtain ⟨_, _, a, c0, no, _⟩ := bound s cs sL p
          cases no
      | some ag =>
          have headK : exists c0, K.head? = some c0 := by
            cases K with
            | nil => simp [Exec.agreementGo] at hag
            | cons c0 _ => exact ⟨c0, rfl⟩
          obtain ⟨c0, head⟩ := headK
          simp only [head, Option.map_some, Option.getD_some] at run
          by_cases big : ag > v.lastIdx
          · simp [big, throw, throwThe, MonadExceptOf.throw] at run
          simp only [big, ite_false] at run
          cases hnc : v.highestCommittableLe ag with
          | none =>
              simp only [hnc, pure, Except.pure, Except.ok.injEq] at run
              subst run
              refine ⟨fun _ s cs sL p => ?_, fun i no => by cases no⟩
              obtain ⟨sig, _, a, c1, same, _, _, sa⟩ := bound s cs sL p
              cases same
              exact highestCommittableLe_none h.committable hnc s (by omega) sL sa sig
          | some nc =>
              obtain ⟨lo, hi, le, sigNc, above⟩ :=
                highestCommittableLe_some h.committable hnc
              have below : forall s, c < s -> s <= v.lastIdx
                  -> cleanP (abs names v) (names.id v.nodeId) c s
                  -> SigAt v s /\ v.viewAt s = v.currentView /\ c0.idx <= s /\ s <= nc := by
                intro s cs sL p
                obtain ⟨sig, view, a, c1, same, head', le0, sa⟩ := bound s cs sL p
                cases same
                rw [head] at head'
                cases head'
                refine ⟨sig, view, le0, ?_⟩
                apply Classical.byContradiction
                intro gt
                exact above s (by omega) sL sa sig
              have getTerm : v.getTerm nc = v.viewAt nc := by
                unfold State.getTerm
                split
                · omega
                · rfl
              simp only [hnc] at run
              by_cases early : nc < c0.idx
              · simp only [early, ite_true, pure, Except.pure, Except.ok.injEq] at run
                subst run
                refine ⟨fun _ s cs sL p => ?_, fun i no => by cases no⟩
                have := below s cs sL p
                omega
              simp only [early, ite_false] at run
              by_cases term : (v.getTerm nc != v.currentView) = true
              · simp only [term, ite_true, pure, Except.pure, Except.ok.injEq] at run
                subst run
                refine ⟨fun _ s cs sL p => ?_, fun i no => by cases no⟩
                obtain ⟨_, view, _, snc⟩ := below s cs sL p
                have m1 := viewAt_mono v snc
                have m2 := viewAt_le_size v nc
                have := h.viewsBounded
                simp only [bne_iff_ne, ne_eq, getTerm] at term
                omega
              simp only [term, Bool.false_eq_true, ite_false, pure, Except.pure, Except.ok.injEq] at run
              subst run
              simp only [bne_iff_ne, ne_eq, getTerm, Decidable.not_not] at term
              refine ⟨(fun no => by cases no), fun i same => ?_⟩
              cases same
              refine ⟨lo, hi, fun s gt cs sL p => ?_, fun cnc => ?_⟩
              · have := below s cs sL p
                omega
              · apply stepTo nc (by omega) hi
                refine ⟨sigNc, term, (spec nc hi).mpr ⟨ag, c0, rfl, head, by omega, le⟩⟩

end Round

/-! ## The loop of `update_commit` -/

section Loop

open Consensus.TraceValidation (Names abs signaturesIn)

/-- `update_commit`'s outer loop as a function of the (unchanging) declared state. -/
def updateCommitOf (v : State) (first : Nat) (newCommit : Option Nat)
    : Nat -> Except String (Option Nat)
  | 0 => .error "update_commit does not terminate"
  | fuel + 1 =>
      match Exec.highestCommittableIdxOf v first with
      | .error e => .error e
      | .ok none => .ok newCommit
      | .ok (some i) =>
          if newCommit.any (i <= ·) then
            .ok newCommit
          else
            updateCommitOf v
              (Exec.advanceFirst v.configurations i first v.configurations.length)
              (some i) fuel

variable {names : Names} {v : State}

theorem firstAt_mono (D : List Config) {c i : Nat} (ci : c <= i)
    : firstAt D c <= firstAt D i := by
  unfold firstAt
  simp only [← List.countP_eq_length_filter]
  apply List.countP_mono_left
  intro x _ h
  simp only [decide_eq_true_eq] at h ⊢
  omega

theorem updateCommitOf_reach (h : Hyps names v) (L0 : 0 < v.lastIdx)
    : forall fuel c newCommit r,
        c = newCommit.getD v.commitIdx
        -> v.commitIdx <= c
        -> Reach (cleanP (abs names v) (names.id v.nodeId)) v.commitIdx v.lastIdx c
        -> updateCommitOf v (firstAt v.configurations c) newCommit fuel = .ok r
        -> Reach (cleanP (abs names v) (names.id v.nodeId)) v.commitIdx v.lastIdx
              (r.getD v.commitIdx)
            /\ Final (cleanP (abs names v) (names.id v.nodeId)) v.lastIdx
                (r.getD v.commitIdx)
  | 0, _, _, _, _, _, _, run => by simp [updateCommitOf] at run
  | fuel + 1, c, newCommit, r, hc, cic, reach, run => by
      simp only [updateCommitOf] at run
      split at run
      · cases run
      · rename_i found
        cases run
        rw [← hc]
        exact ⟨reach, (round h L0 cic found).1 rfl⟩
      · rename_i i found
        obtain ⟨lo, hi, quiet, step⟩ := (round h L0 cic found).2 i rfl
        split at run
        · rename_i stop
          cases run
          rw [← hc]
          refine ⟨reach, fun s cs sL p => ?_⟩
          cases newCommit with
          | none => simp at stop
          | some n =>
              simp only [Option.any_some, decide_eq_true_eq] at stop
              simp only [Option.getD_some] at hc
              exact quiet s (by omega) cs sL p
        · rename_i go
          have ci : c < i := by
            cases newCommit with
            | none =>
                simp only [Option.getD_none] at hc
                omega
            | some n =>
                simp only [Option.any_some, decide_eq_true_eq] at go
                simp only [Option.getD_some] at hc
                omega
          have next := Reach.step reach ci hi (step ci)
          rw [advanceFirst_eq (h.sorted L0) i _ _ (firstAt_mono _ (by omega))
            (by have := firstAt_le_length v.configurations i; omega)] at run
          exact updateCommitOf_reach h L0 fuel i (some i) r rfl (by omega) next run

theorem highestCommittableIdxOf_empty
    (committable : v.committable = signaturesIn v v.commitIdx v.lastIdx)
    (L0 : v.lastIdx = 0) {first : Nat} {r : Option Nat}
    (run : Exec.highestCommittableIdxOf v first = .ok r)
    : r = none := by
  have none_ : forall a, v.highestCommittableLe a = none := by
    intro a
    have : v.committable = [] := by
      rw [committable]
      simp [signaturesIn, L0]
    simp [State.highestCommittableLe, this]
  unfold Exec.highestCommittableIdxOf at run
  simp only [bind, Except.bind] at run
  split at run
  · cases run
  · rename_i r' _
    cases r' with
    | none =>
        simp only [pure, Except.pure, Except.ok.injEq] at run
        exact run.symm
    | some a =>
        simp only [none_] at run
        by_cases big : a > v.lastIdx
        · simp [big, throw, throwThe, MonadExceptOf.throw] at run
        · simp only [big, ite_false, pure, Except.pure, Except.ok.injEq] at run
          exact run.symm

/--
`update_commit` chooses the clean `highestCommittableIndex`: when its loop returns `r`, the
clean fold from the declared state ends at `r`, or at the commit index when `r` is `none`.
-/
theorem updateCommit_eq (h : Hyps names v) {fuel : Nat} {r : Option Nat}
    (run : updateCommitOf v 0 none fuel = .ok r)
    : highestCommittableIndex (abs names v) (names.id v.nodeId) = r.getD v.commitIdx := by
  obtain ⟨cleanReach, cleanFinal⟩ := highestCommittableIndex_reach (abs names v) (names.id v.nodeId)
  have len : (abs names v).log.length = v.lastIdx := abs_log_length h.size
  have ci : (abs names v).commitIndex = v.commitIdx := rfl
  rw [len, ci] at cleanReach
  rw [len] at cleanFinal
  by_cases L0 : v.lastIdx = 0
  · have : r = none := by
      cases fuel with
      | zero => simp [updateCommitOf] at run
      | succ fuel =>
          simp only [updateCommitOf] at run
          split at run
          · cases run
          · cases run
            rfl
          · rename_i i found
            cases highestCommittableIdxOf_empty h.committable L0 found
    subst this
    have := cleanReach.ge
    have := cleanReach.le h.commitLe
    simp only [Option.getD_none]
    omega
  · have L0 : 0 < v.lastIdx := by omega
    have first : firstAt v.configurations v.commitIdx = 0 := h.firstAt_self L0
    rw [← first] at run
    obtain ⟨r1, f1⟩ := updateCommitOf_reach h L0 fuel v.commitIdx none r rfl (Nat.le_refl _)
      .base run
    exact reach_final_unique (cleanP_mono _ _) cleanReach cleanFinal r1 f1

end Loop

/-! ## The monadic loop -/

section Monadic

open Consensus.TraceValidation.Proofs (Spec)

theorem liftE_spec {env : Consensus.TraceValidation.Env} {α : Type} (x : Except String α)
    : Spec env (Exec.liftE x) fun v o a v' o' => x = .ok a /\ v' = v /\ o' = o := by
  unfold Exec.liftE
  split
  · refine Spec.weaken (Spec.pure _) ?_
    rintro _ _ _ _ _ ⟨rfl, rfl, rfl⟩
    exact ⟨rfl, rfl, rfl⟩
  · refine Spec.weaken
      (Spec.bind Spec.curLoc fun _ => Spec.fail (P := fun _ _ _ _ _ => False) _) ?_
    rintro _ _ _ _ _ ⟨_, _, _, _, f⟩
    exact f.elim

/-- The monadic loop computes `updateCommitOf` and changes neither state nor outbox. -/
theorem updateCommitGo_spec {env : Consensus.TraceValidation.Env}
    : forall fuel first newCommit,
        Spec env (Exec.updateCommitGo first newCommit fuel)
          fun v o r v' o' =>
            v' = v /\ o' = o /\ updateCommitOf v first newCommit fuel = .ok r
  | 0, first, newCommit => by
      simp only [Exec.updateCommitGo]
      exact Spec.fail _
  | fuel + 1, first, newCommit => by
      simp only [Exec.updateCommitGo, Exec.highestCommittableIdx]
      refine Spec.weaken
        (Spec.bind (Spec.bind Spec.getV fun v => liftE_spec _)
          (Q := fun r v o res v' o' =>
            v' = v /\ o' = o
            /\ match r with
              | none => res = newCommit
              | some i =>
                  if (newCommit.any fun x => decide (i <= x)) = true then res = newCommit
                  else
                    updateCommitOf v
                        (Exec.advanceFirst v.configurations i first v.configurations.length)
                        (some i) fuel
                      = .ok res)
          fun r => ?_) ?_
      · cases r with
        | none =>
            refine Spec.weaken (Spec.pure _) ?_
            rintro _ _ _ _ _ ⟨rfl, rfl, rfl⟩
            exact ⟨rfl, rfl, rfl⟩
        | some i =>
            dsimp only
            by_cases b : (newCommit.any fun x => decide (i <= x)) = true
            · simp only [b, ite_true]
              refine Spec.weaken (Spec.pure _) ?_
              rintro _ _ _ _ _ ⟨rfl, rfl, rfl⟩
              exact ⟨rfl, rfl, rfl⟩
            · simp only [b, Bool.false_eq_true, ite_false]
              refine Spec.weaken
                (Spec.bind Spec.getV fun w => updateCommitGo_spec fuel _ _) ?_
              rintro _ _ _ _ _ ⟨_, _, _, ⟨rfl, rfl, rfl⟩, rfl, rfl, loop⟩
              exact ⟨rfl, rfl, loop⟩
      · rintro v o r v'' o'' ⟨found, v', o', ⟨w, v1, o1, ⟨rfl, rfl, rfl⟩, run, rfl, rfl⟩, rfl, rfl, rest⟩
        refine ⟨rfl, rfl, ?_⟩
        simp only [updateCommitOf, run]
        cases found with
        | none => simpa using rest.symm
        | some i =>
            by_cases b : (newCommit.any fun x => decide (i <= x)) = true
            · simp only [b, ite_true] at rest ⊢
              rw [rest]
            · simp only [b, Bool.false_eq_true, ite_false] at rest ⊢
              exact rest

end Monadic

/-! ## `Hyps` from the invariant -/

section OfInv

open Consensus.TraceValidation (Names abs signaturesIn inv invChecks configurationsMatch)

theorem nodup_eraseDups {α : Type} [BEq α] [LawfulBEq α]
    : forall (n : Nat) (l : List α), l.length <= n -> l.eraseDups.Nodup
  | _, [], _ => by simp
  | 0, _ :: _, h => by simp at h
  | n + 1, a :: as, h => by
      rw [List.eraseDups_cons]
      refine List.nodup_cons.mpr ⟨?_, ?_⟩
      · rw [List.mem_eraseDups, List.mem_filter]
        simp
      · apply nodup_eraseDups n
        have := List.length_filter_le (fun b => !b == a) as
        simp only [List.length_cons] at h
        omega

theorem nodup_of_eraseDups_eq {α : Type} [BEq α] [LawfulBEq α] {l : List α}
    (h : l.eraseDups = l)
    : l.Nodup := by
  rw [← h]
  exact nodup_eraseDups _ l (Nat.le_refl _)

/-- A conjunct of `inv`, looked up by name. -/
theorem inv_conjunct {names : Names} {v : State} (h : inv names v = true) (n : String)
    : ((invChecks names v).lookup n).getD true = true := by
  unfold inv at h
  generalize invChecks names v = l at h
  induction l with
  | nil => rfl
  | cons x l ih =>
      obtain ⟨k, b⟩ := x
      simp only [List.all_cons, Bool.and_eq_true] at h
      simp only [List.lookup_cons]
      split
      · exact h.1
      · exact ih h.2

theorem configurationsMatch_spec {ci : Nat}
    : forall {ds cs : List (Nat × List NodeID)},
        configurationsMatch ci ds cs = true
        -> ds = cs
            \/ exists i j n rest,
                ds = (i, n) :: rest /\ cs = (j, n) :: rest /\ j <= i /\ i <= ci
  | [], [], _ => Or.inl rfl
  | [], _ :: _, h => by simp [configurationsMatch] at h
  | _ :: _, [], h => by simp [configurationsMatch] at h
  | (i, n) :: ds, (j, m) :: cs, h => by
      simp only [configurationsMatch, Bool.and_eq_true, beq_iff_eq, Bool.or_eq_true,
        decide_eq_true_eq] at h
      obtain ⟨⟨rfl, ij⟩, rfl⟩ := h
      rcases ij with rfl | ⟨ji, ic⟩
      · exact Or.inl rfl
      · exact Or.inr ⟨i, j, n, ds, rfl, rfl, ji, ic⟩

theorem Hyps.ofInv {names : Names} {v : State} (h : inv names v = true)
    : Hyps names v := by
  have c1 := inv_conjunct h "ledger_size"
  have c2 := inv_conjunct h "commit_le_last"
  have c3 := inv_conjunct h "committable"
  have c4 := inv_conjunct h "terms_are_views"
  have c5 := inv_conjunct h "views_bounded"
  have c6 := inv_conjunct h "configurations"
  have c7 := inv_conjunct h "self_named"
  have c8 := inv_conjunct h "names_round_trip"
  have c9 := inv_conjunct h "configuration_members_distinct"
  simp only [invChecks, List.lookup_cons, List.lookup_nil] at c1 c2 c3 c4 c5 c6 c7 c8 c9
  simp only [String.reduceBEq, Option.getD_some, beq_iff_eq, decide_eq_true_eq, Bool.or_eq_true,
    List.all_eq_true] at c1 c2 c3 c4 c5 c6 c7 c8 c9
  refine ⟨c1, c2, c3, ?_, c5, ?_, c7, ?_, ?_, ?_⟩
  · intro i i1 iL
    exact c4 i (List.mem_range'_1.mpr ⟨i1, by omega⟩)
  · intro L0
    rcases c6 with zero | matched
    · omega
    rcases configurationsMatch_spec matched with same | ⟨i, j, n, rest, hd, hc, ji, ic⟩
    · exact ⟨_, configs_of_map names _ _ same, Or.inl rfl⟩
    obtain ⟨y, E, hE, hy, hE'⟩ := List.map_eq_cons_iff.mp hd
    obtain ⟨a, A, hA, ha, hA'⟩ := List.map_eq_cons_iff.mp hc
    simp only [Prod.mk.injEq] at hy ha
    have yi := hy.1
    have aj := ha.1
    have ac : (abs names v).commitIndex = v.commitIdx := rfl
    rw [ac] at hA
    refine ⟨{ y with idx := j } :: E, configs_of_map names _ _ ?_, Or.inr
      ⟨{ y with idx := j }, y, E, rfl, hE, rfl, by simp only; omega, by omega⟩⟩
    rw [hA]
    simp only [List.map_cons, hE', hA', ha.1, ha.2, hy.2]
  · intro p mem
    exact c8 p.1 (List.mem_append_right _ (List.mem_map_of_mem mem))
  · intro x mem a member
    exact c8 a.1 (List.mem_append_left _
      (List.mem_flatMap.mpr ⟨x, mem, List.mem_map_of_mem member⟩))
  · intro x mem
    exact nodup_of_eraseDups_eq (c9 x mem)

/--
`update_commit` on a declared state that satisfies `inv` chooses the clean
`highestCommittableIndex`.
-/
theorem updateCommit_eq_of_inv {names : Names} {v : State} (h : inv names v = true)
    {fuel : Nat} {r : Option Nat} (run : updateCommitOf v 0 none fuel = .ok r)
    : highestCommittableIndex (abs names v) (names.id v.nodeId) = r.getD v.commitIdx :=
  updateCommit_eq (Hyps.ofInv h) run

end OfInv

end Consensus.TraceValidation.Proofs.ReplUpdateCommit
