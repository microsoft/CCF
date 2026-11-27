module

public import DisasterRecovery.Proofs.Refinement

import all Init.Control.State

@[expose] public section

namespace DisasterRecovery.Proofs.Atomic

open CCF OCC

/-- The concrete state at the boundary between two serialized handlers. -/
structure Clean (before : Model.Local.NodeState) (s : NodeState) : Prop where
  represented : Represents (values before.store) s
  location : before.location = s.location
  pending : before.pending = []

/-- A successful atomic step on an idle node is implemented by a run followed
by a commit on the same snapshot. -/
theorem run_commit (c : Config) (node : Location) (tx : TxID) (before : Model.Local.NodeState)
    (s after : NodeState) (clean : Clean before s) (e : Event) (ne : e ≠ .retry)
    (out : Outputs Location Message Notification)
    (accepted : ∀ reason, out.notifications ≠ [.rejected reason])
    (atomic : (step (Capabilities.record node) c tx s e).run {} = some (after,out)) :
    ∃ mid last early, (Model.Local.perform (Capabilities.record node) c tx before (.run e)).run {} =
        some (mid,early) ∧ early.outgoing = [] ∧
      (Model.Local.perform (Capabilities.record node) c tx mid (.commit 0)).run {} = some (last,out) ∧
      Clean last after := by
  let body := Model.Local.transaction c e
  let ran := body.exec before.store
  have serial := Program.serial_eq_execFrom before.store {} [] body
  change body.serial (values before.store) [] = ran.result.map _ at serial
  have agrees := event_agrees c node tx s _ clean.represented e ne
  change EventAgrees node s (body.serial (values before.store) []) _ at agrees
  rw [serial,atomic] at agrees
  cases ok : ran.result with
  | error reason =>
    rw [ok] at agrees
    rcases agrees with bad | ⟨why,bad⟩
    · contradiction
    · exact False.elim (accepted why (congrArg (fun p => p.2.notifications) (Option.some.inj bad)))
  | ok u =>
    cases u
    rw [ok] at agrees
    obtain ⟨spec,rep,loc,eq⟩ := agrees
    obtain ⟨rfl,rfl⟩ := Prod.mk.inj (Option.some.inj eq)
    let a : Model.Local.Attempt := ⟨e,ran.normal,ran.outputs⟩
    let mid := {before with pending := [a]}
    have start : (Model.Local.perform (Capabilities.record node) c tx before (.run e)).run {} =
        some (mid,Evaluation.recordOutputs node {} (Model.Local.unguarded ran.outputs)) := by
      have h : Model.Local.perform (Capabilities.record node) c tx before (.run e) = Model.Local.start _ c before e := by
        cases e <;> first | rfl | contradiction
      rw [h]
      simp only [Model.Local.start,show ((Model.Local.transaction c e).exec before.store).result = .ok () from ok]
      change ((Model.Local.release _ _).run {}).bind _ = _
      rw [Evaluation.release_record]
      simp [mid,a,ran,body,clean.pending]
    refine ⟨mid,_,_,start,(Evaluation.unguarded_frame node _).1,?_⟩
    have valid := Program.exec_valid before.store body
    change validates before.store ran.normal.deps = true at valid
    simp only [Model.Local.perform,mid,List.getElem?_cons_zero, a]
    by_cases empty : ran.normal.writes.isEmpty = true
    · simp only [empty,reduceIte]
      change _ ∧ Clean _ _
      constructor
      · change ((Model.Local.release _ _).run {}).bind _ = _
        rw [Evaluation.release_record]; rfl
      · change Represents (overlay before.store ran.normal.writes) _ at rep
        rw [List.isEmpty_iff.mp empty] at rep
        exact ⟨rep,clean.location.trans loc.symm,rfl⟩
    · simp only [empty,valid,reduceIte]
      constructor
      · change ((Model.Local.release _ _).run {}).bind _ = _
        rw [Evaluation.release_record]; rfl
      · refine ⟨?_,clean.location.trans loc.symm,rfl⟩
        exact (overlay_publish before.store ran.normal.writes (before.version+1)) ▸ rep

end DisasterRecovery.Proofs.Atomic
