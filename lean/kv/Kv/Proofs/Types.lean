-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Kv.Protocol.Types

/-! Supporting lemmas for the erased certificates carried by the executable model. -/

namespace Kv.Proofs.Types

theorem normalRun_append [DecidableEq M] [DecidableEq K] [DecidableEq V]
    (db : DB M K V) (n : Normal M K V) (a b : List (NormalOp M K V)) :
    normalRun db n (a ++ b) =
      (normalRun db n a).bind (fun next => normalRun db next b) := by
  induction a generalizing n with
  | nil => rfl
  | cons op ops ih =>
    cases hs : normalStep db n op <;> simp [normalRun, hs, ih]

theorem normalStep_log [DecidableEq M] [DecidableEq K] [DecidableEq V]
    (db : DB M K V) (n n' : Normal M K V) (op : NormalOp M K V)
    (h : normalStep db n op = some n') : n'.log = n.log ++ [op] := by
  unfold normalStep at h
  split at h
  next => cases h; rfl
  next => simp at h

theorem normalRun_extend [DecidableEq M] [DecidableEq K] [DecidableEq V]
    (db : DB M K V) (n n' : Normal M K V) (op : NormalOp M K V)
    (before : normalRun db {} n.log = some n)
    (one : normalStep db n op = some n') :
    normalRun db {} n'.log = some n' := by
  rw [normalStep_log db n n' op one, normalRun_append, before]
  simp [normalRun, one]

theorem History.bounded (fs : List Frame) (n : Nat) (h : History fs n) :
    ∀ f ∈ fs, f.version ≤ n := by
  induction h with
  | zero =>
    intro g hg
    have he : g = {} := List.mem_singleton.mp hg
    subst g
    exact Nat.le_refl 0
  | succ f n fs hv effect tail ih =>
    intro g hg
    rcases List.mem_cons.mp hg with he | hm
    · subst g; omega
    · exact Nat.le_trans (ih g hm) (Nat.le_succ n)

theorem History.cut (fs : List Frame) (n : Nat) (h : History fs n)
    (cut : Nat) (hc : cut ≤ n) :
    ∃ f, fs.find? (fun f => f.version ≤ cut) = some f ∧ f.version = cut ∧
      History (fs.filter fun f => f.version ≤ cut) cut ∧
      (fs.filter fun f => f.version ≤ cut).head? = some f := by
  induction h with
  | zero =>
    have hz : cut = 0 := by omega
    subst cut
    refine ⟨{}, ?_, rfl, ?_, ?_⟩
    · rfl
    · exact .zero
    · rfl
  | succ f n fs hv effect tail ih =>
    by_cases he : cut = n + 1
    · subst cut
      have hall : (f :: fs).filter (fun f => decide (f.version ≤ n + 1)) = f :: fs := by
        apply List.filter_eq_self.mpr
        intro g hg
        simp only [decide_eq_true_eq]
        exact History.bounded _ _ (.succ f n fs hv effect tail) g hg
      refine ⟨f, by simp [List.find?, hv], hv, ?_, by simp [hall]⟩
      rw [hall]
      exact .succ f n fs hv effect tail
    · have hlt : ¬n + 1 ≤ cut := by omega
      have hc' : cut ≤ n := by omega
      obtain ⟨g, found, gv, shape, first⟩ := ih hc'
      refine ⟨g, ?_, gv, ?_, ?_⟩
      · simpa [List.find?, hv, hlt] using found
      · simpa [hv, hlt] using shape
      · simpa [hv, hlt] using first

theorem atCut_spec (s : Store) (cut : Nat) (hc : cut ≤ s.head.version) :
    (atCut s cut).version = cut ∧
      History (s.history.filter fun f => f.version ≤ cut) cut ∧
      (s.history.filter fun f => f.version ≤ cut).head? = some (atCut s cut) := by
  obtain ⟨f, found, version, shape, first⟩ :=
    History.cut s.history s.head.version s.historyShape cut hc
  simpa [atCut, found] using And.intro version (And.intro shape first)

theorem operation_certificate (t : Tx) (snap : Snapshot)
    (n : Normal String String String) (op : NormalOp String String String)
    (hs : t.snapshot = some snap)
    (hn : normalStep snap.current.data t.normal op = some n) :
    match t.snapshot with
    | none => n = {}
    | some snap => normalRun snap.current.data {} n.log = some n := by
  have old : normalRun snap.current.data {} t.normal.log = some t.normal := by
    simpa [hs] using t.certificate
  simpa [hs] using normalRun_extend snap.current.data t.normal n op old hn

theorem snapshot_certificate (t : Tx) (data : Data) (hs : t.snapshot = none) :
    normalRun data {} t.normal.log = some t.normal := by
  have hzero : t.normal = {} := by simpa [hs] using t.certificate
  simp [hzero, normalRun]

theorem history_extension (s : Store) (f : Frame) (writes : Pending)
    (version : f.version = s.head.version + 1)
    (data : f.data = publish s.head.data (s.head.version + 1) writes) :
    History (f :: s.history) (s.head.version + 1) :=
  .succ f s.head.version s.history version
    ⟨writes, by simpa only [s.headFirst, Option.getD_some] using data⟩ s.historyShape

theorem cut_history (s : Store) (cut : Nat) (within : cut ≤ s.head.version) :
    History (s.history.filter fun f => f.version ≤ cut) (atCut s cut).version := by
  have spec := atCut_spec s cut within
  rw [spec.1]
  exact spec.2.1

theorem cut_global_bound (s : Store) (cut : Nat)
    (within : cut ≤ s.head.version) (boundary : s.global ≤ cut) :
    s.global ≤ (atCut s cut).version := by
  rw [(atCut_spec s cut within).1]
  exact boundary

end Kv.Proofs.Types
