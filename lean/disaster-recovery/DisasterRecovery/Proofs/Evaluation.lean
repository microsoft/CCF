module

public import DisasterRecovery.Properties.Utils
public import CCF.Proofs.Execution

import all Init.Control.State

@[expose] public section

namespace DisasterRecovery.Proofs.Evaluation

open CCF Model.Local

/-- Effects of handing the transaction's ordered outputs to the recording host. -/
def recordOutputs (node : Location) (outputs : Outputs Location Message Notification)
    : List Output → Outputs Location Message Notification
  | [] => outputs
  | .notify n :: rest =>
      recordOutputs node { outputs with notifications := outputs.notifications ++ [n] }
        rest
  | .send message target :: rest =>
      recordOutputs node
        {
          outputs with
            outgoing :=
              outputs.outgoing ++ [{ source := node, target, payload := message }]
        } rest

theorem release_record (node : Location) (outputs : Outputs Location Message Notification)
    (items : List Output)
    : (release (Capabilities.record node) items).run outputs
      = some ((), recordOutputs node outputs items) := by
  induction items generalizing outputs with
  | nil => rfl
  | cons item rest ih =>
      cases item <;> apply ih

private theorem onlyRestarts (node : Location) (items : List Output)
    (outs : Outputs Location Message Notification)
    (only : ∀ x ∈ items, ∃ n, x = .notify (.restart n))
    : (recordOutputs node outs items).outgoing = outs.outgoing
      ∧ ∀ k,
          .opening k ∉ outs.notifications
          → .opening k ∉ (recordOutputs node outs items).notifications := by
  induction items generalizing outs with
  | nil => exact ⟨rfl,fun _ h => h⟩
  | cons x rest ih =>
      obtain ⟨n,rfl⟩ := only x List.mem_cons_self
      have tail := ih {outs with notifications := outs.notifications ++ [.restart n]}
        (fun y h => only y (List.mem_cons_of_mem _ h))
      exact ⟨tail.1,fun k h => tail.2 k (by simpa using h)⟩

/-- Run-time restart callbacks cannot deliver protocol messages or announce an opening. -/
theorem unguarded_frame (node : Location) (items : List Output)
    : (recordOutputs node {} (unguarded items)).outgoing = []
      ∧ ∀ k, .opening k ∉ (recordOutputs node {} (unguarded items)).notifications := by
  have only (x) (h : x ∈ unguarded items) : ∃ n, x = .notify (.restart n) := by
    obtain ⟨_,h⟩ := List.mem_filter.mp h
    cases x with
    | send => contradiction
    | notify n => cases n <;> first | contradiction | exact ⟨_,rfl⟩
  have frame := onlyRestarts node _ {} only
  exact ⟨frame.1,fun k => frame.2 k (by simp)⟩

/-- A stale read-only commit with restart-only outputs cannot send or open. -/
theorem restart_frame (node : Location) (items : List Output)
    (only : ∀ x ∈ items, ∃ n, x = .notify (.restart n))
    : (recordOutputs node {} items).outgoing = []
      ∧ ∀ k, .opening k ∉ (recordOutputs node {} items).notifications :=
  ⟨(onlyRestarts node _ {} only).1,fun k => (onlyRestarts node _ {} only).2 k (by simp)⟩

theorem timeout_enabled (node : Location) (config : Config) (recovered : TxID)
    (state : NodeState)
    : ∃ after effects,
        (perform (Capabilities.record node) config recovered state (.run .timeout)).run {}
        = some (after, effects) := by
  simp only [perform, start]
  cases h : ((transaction config .timeout).exec state.store).result with
  | error reason => exact ⟨_, _, rfl⟩
  | ok result =>
      cases result
      change ∃ after effects, ((release _ _).run {}).bind _ = some (after, effects)
      rw [release_record]
      exact ⟨_, _, rfl⟩

end DisasterRecovery.Proofs.Evaluation
