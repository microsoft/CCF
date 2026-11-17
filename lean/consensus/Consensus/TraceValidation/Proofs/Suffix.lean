module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.TraceValidation.Proofs.Obligation

@[expose] public section

/-!
# The declared state holds a suffix (proof, not reviewed)

M_tv's handlers run on the whole ledger (`Exec.State`); the reviewed declared state
(`Exec.Declared`) holds the entries after the snapshot base. Given `inv` and the release
check `baseOk`, the proof relation's `agrees` on the whole ledger gives the reviewed
`Exec.Declared.agrees` of the projection `State.declared`.
-/

namespace Consensus.TraceValidation.Proofs

open Consensus.Model.Node
open Consensus.TraceValidation.Exec (State)

private theorem inv_lookup {names : Names} {v : State} (h : inv names v = true)
    (n : String)
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

theorem inv_ledger {names : Names} {d : State} (h : inv names d = true)
    : d.ledger.size = d.lastIdx /\ d.commitIdx <= d.lastIdx := by
  have c1 := inv_lookup h "ledger_size"
  have c2 := inv_lookup h "commit_le_last"
  simp only [invChecks, List.lookup_cons, List.lookup_nil] at c1 c2
  simp only [String.reduceBEq, Option.getD_some, beq_iff_eq, decide_eq_true_eq] at c1 c2
  exact ⟨c1, c2⟩

/-- The whole clean log, after the base, is the held entries. -/
theorem held_log {names : Names} {d : State}
    : (abs names d).log.drop d.base = (d.declared.abs names).log := by
  simp only [abs, Exec.Declared.abs, State.declared, Array.toList_extract,
    List.extract_eq_take_drop, ← List.map_drop, List.drop_take, List.take_take]
  congr 1
  rw [List.take_eq_take_iff]
  simp only [List.length_drop, Array.length_toList]
  omega

theorem agrees_declared {names : Names} {c : NodeState} {d : State}
    (agreed : agrees names c d = true) (size : d.ledger.size = d.lastIdx)
    (ok : baseOk d = true)
    : d.declared.agrees names c = true := by
  simp only [baseOk, Bool.and_eq_true, decide_eq_true_eq, Bool.or_eq_true, beq_iff_eq] at ok
  obtain ⟨bc, bsig⟩ := ok
  have log : c.log = (abs names d).log := by
    simp only [agrees, Bool.and_eq_true, beq_iff_eq] at agreed
    exact agreed.1.1.1.1.1.1.1.1.2
  have sig : (d.declared.base == 0
      || c.log[d.declared.base - 1]? == some { term := d.declared.baseView, content := .signature })
      = true := by
    show (d.base == 0
      || c.log[d.base - 1]? == some { term := d.baseView, content := .signature }) = true
    rcases bsig with zero | at_
    · simp [zero]
    cases found : d.ledger[d.base - 1]? with
    | none => simp [found] at at_
    | some e =>
        simp only [found, Option.any_some, Bool.and_eq_true, beq_iff_eq] at at_
        have lt : d.base - 1 < d.ledger.size := by
          rcases Array.getElem?_eq_some_iff.mp found with ⟨lt, _⟩
          exact lt
        rw [log]
        simp [abs, show d.base - 1 < d.lastIdx by omega, found, absEntry, at_.1, at_.2]
  have drop : (c.log.drop d.declared.base == (d.declared.abs names).log)
      = (c.log == (abs names d).log) := by
    rw [log, beq_self_eq_true, show d.declared.base = d.base from rfl, held_log,
      beq_self_eq_true]
  unfold Exec.Declared.agrees
  simp only
  rw [sig, drop, Bool.true_and]
  have bc' : decide (d.declared.base <= d.declared.commitIdx) = true := by
    simp only [decide_eq_true_eq]; exact bc
  rw [bc', Bool.true_and]
  exact agreed

/-- The proof relation, with the release check `baseOk`, gives the reviewed `related`. -/
theorem related_declared {env : Env} {node : NodeID} {c : NodeState} {d : State}
    (h : Rel env node c d) (ok : baseOk d = true)
    : related env.names node c d.declared = true := by
  obtain ⟨_, rid, rinv, disj, _⟩ := h
  obtain ⟨size, le⟩ := inv_ledger rinv
  simp only [related, Bool.and_eq_true, beq_iff_eq, Bool.or_eq_true]
  refine ⟨rid, ?_⟩
  rcases disj with ⟨_, agreed⟩ | ⟨isPristine, rfl⟩
  · exact Or.inl (agrees_declared agreed size ok)
  · simp only [pristine, Bool.and_eq_true, beq_iff_eq] at isPristine
    simp only [baseOk, Bool.and_eq_true, decide_eq_true_eq] at ok
    refine Or.inr ⟨⟨isPristine.2, ?_⟩, rfl⟩
    show d.base = 0
    omega

end Consensus.TraceValidation.Proofs
