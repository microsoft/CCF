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

/-- Every recorded notification was already present or came from a `.notify` output. -/
theorem recordOutputs_mem_notifications (node : Location)
    (outs : Outputs Location Message Notification) (items : List Output)
    (n : Notification)
    (mem : n ∈ (recordOutputs node outs items).notifications)
    : n ∈ outs.notifications ∨ .notify n ∈ items := by
  induction items generalizing outs with
  | nil => exact Or.inl mem
  | cons item rest ih =>
      cases item with
      | send message target =>
          rcases ih _ mem with old | tail
          · exact Or.inl old
          · exact Or.inr (List.mem_cons_of_mem _ tail)
      | notify m =>
          rcases ih _ mem with old | tail
          · simp only [List.mem_append, List.mem_singleton] at old
            rcases old with prev | rfl
            · exact Or.inl prev
            · exact Or.inr List.mem_cons_self
          · exact Or.inr (List.mem_cons_of_mem _ tail)

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
      exact ⟨_, _, rfl⟩

end DisasterRecovery.Proofs.Evaluation
