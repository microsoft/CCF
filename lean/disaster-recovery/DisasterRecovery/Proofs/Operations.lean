module

public import DisasterRecovery.Proofs.Refinement

import all Init.Control.State

@[expose] public section

namespace DisasterRecovery.Proofs.Atomic

open CCF OCC
open Model.Local (Operation Attempt)

/-- The queue after the operation carries only events that were already pending
or were supplied to that run. A conflict may replace the attempt, not its event. -/
def ComesFrom (st : Model.Local.NodeState) (op : Operation) (e : Event) : Prop :=
  (∃ a ∈ st.pending, a.event = e) ∨ op = .run e

/-- All ways a local operation can affect the serialized history. -/
structure LocalRefinement (config : Model.Config) (node : Location) (tx : TxID)
    (before : Model.Local.NodeState) (op : Operation) (after : Model.Local.NodeState)
    (out : Outputs Location Message Notification)
    : Prop where
  /-- The store still represents the projected state. -/
  represented : Represents (values after.store) (project after)
  /-- Every pending event has an origin. -/
  pending : ∀ a ∈ after.pending, ComesFrom before op a.event
  /-- A real action either stutters for these properties, or serializes a retry or commit. -/
  serialized
    : (project after = project before
        ∧ out.outgoing = []
        ∧ ∀ k, .opening k ∉ out.notifications)
      ∨ ∃ e,
          (e = .retry ∨ ∃ a ∈ before.pending, a.event = e)
          ∧ (step (Capabilities.record node) config.protocol tx (project before) e).run {}
            = some (project after,out)

private theorem start_cases (c : Model.Config) (node : Location) (tx : TxID)
    (before base after : Model.Local.NodeState) (op : Operation) (e : Event)
    (out : Outputs Location Message Notification)
    (r : Represents (values base.store) (project base))
    (same : project base = project before) (origin : ComesFrom before op e)
    (basePending : ∀ a ∈ base.pending, ComesFrom before op a.event)
    (run
      : (Model.Local.start (Capabilities.record node) c.protocol base e).run {}
        = some (after,out))
    : LocalRefinement c node tx before op after out := by
  cases h : ((Model.Local.transaction c.protocol e).exec base.store).result with
  | error reason =>
      simp only [Model.Local.start,h] at run
      change some (base,({notifications := [.rejected reason]} : Outputs Location Message Notification)) = _ at run
      obtain ⟨rfl,rfl⟩ := Prod.mk.inj (Option.some.inj run)
      exact ⟨r,basePending,Or.inl ⟨same,rfl,by simp⟩⟩
  | ok u =>
      cases u
      simp only [Model.Local.start,h] at run
      change ((Model.Local.release _ _).run {}).bind _ = _ at run
      rw [Evaluation.release_record] at run
      obtain ⟨states,effects⟩ := Prod.mk.inj (Option.some.inj run)
      subst after out
      refine ⟨r,?_,Or.inl ⟨same,Evaluation.unguarded_frame node _⟩⟩
      intro a mem
      rcases List.mem_append.mp mem with old | new
      · exact basePending _ old
      · cases List.mem_singleton.mp new; exact origin

/-- The operation-level refinement used by the global ghost execution. -/
theorem operation_refines (c : Model.Config) (node : Location) (tx : TxID)
    (before after : Model.Local.NodeState) (op : Operation)
    (out : Outputs Location Message Notification)
    (r : Represents (values before.store) (project before))
    (wf : Transactions.WellFormed c.protocol before)
    (run
      : (Model.Local.perform (Capabilities.record node) c.protocol tx before op).run {}
        = some (after,out))
    : LocalRefinement c node tx before op after out := by
  have old (a : Attempt) (h : a ∈ before.pending) : ComesFrom before op a.event :=
    Or.inl ⟨a,h,rfl⟩
  cases op with
  | run e =>
      cases e <;> first | exact start_cases c node tx before before after _ _ out r rfl (Or.inr rfl) old run | contradiction
  | retry =>
      rw [retry_agrees c.protocol node tx before (project before) r rfl] at run
      obtain ⟨⟨next,o⟩,atomic,eq⟩ := Option.map_eq_some_iff.mp run
      obtain ⟨rfl,rfl⟩ := Prod.mk.inj eq
      obtain rfl := retry_state c.protocol node tx atomic
      exact ⟨r,old,Or.inr ⟨.retry,Or.inl rfl,atomic⟩⟩
  | commit i =>
      cases slot : before.pending[i]? with
      | none => simp [Model.Local.perform,slot] at run; contradiction
      | some a =>
          have mem := List.mem_of_getElem? slot
          let rest := {before with pending := before.pending.eraseIdx i}
          have restPending (b : Attempt) (h : b ∈ rest.pending) :=
            old b (List.eraseIdx_subset h)
          simp only [Model.Local.perform,slot] at run
          by_cases empty : a.normal.writes.isEmpty = true
          · simp only [empty] at run
            change ((Model.Local.release _ a.outputs).run {}).bind _ = _ at run
            rw [Evaluation.release_record] at run
            obtain ⟨states,effects⟩ := Prod.mk.inj (Option.some.inj run)
            subst after out
            obtain ⟨snap,ran⟩ := wf.2 a mem
            have frame := Evaluation.restart_frame node a.outputs (fun x h =>
              Transactions.readOnly_only_restart c.protocol a.event snap (by simpa [ran] using empty)
                x (by rwa [ran]))
            exact ⟨r,restPending,Or.inl ⟨rfl,frame⟩⟩
          · simp only [empty] at run
            by_cases valid : validates before.store a.normal.deps = true
            · simp only [valid] at run
              change ((Model.Local.release _ a.outputs).run {}).bind _ = _ at run
              rw [Evaluation.release_record] at run
              obtain ⟨states,effects⟩ := Prod.mk.inj (Option.some.inj run)
              subst after out
              have ne : a.event ≠ .retry := by
                obtain ⟨snap,ran⟩ := wf.2 a mem
                intro eq; rw [eq] at ran
                have bad := congrArg Program.Ran.result ran
                cases bad
              obtain ⟨s,rep,loc,go⟩ :=
                commit_agrees c node tx before (project before) r i a
                  ⟨slot,wf.2 a mem,valid⟩ ne
              have same :=
                rep.project
                  (st :=
                    {
                      rest with
                        store :=
                          publish before.store (before.version + 1) a.normal.writes,
                        version := before.version + 1
                    })
                  loc.symm
              exact ⟨same ▸ rep,restPending,Or.inr ⟨a.event,Or.inr ⟨a,mem,rfl⟩,same ▸ go⟩⟩
            · simp only [valid] at run
              exact start_cases c node tx before rest after _ _ _ r rfl (old a mem)
                restPending run

end DisasterRecovery.Proofs.Atomic
