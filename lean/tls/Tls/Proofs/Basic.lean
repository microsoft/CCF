-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import Tls.Model

@[expose] public section

/-!
Facts about the model's definitions which the invariant proofs share: the shape of the results
of `scheduleTrafficKeys` and `refill`, and `driveReady` unfolded into its stages.
-/

namespace Tls.Proofs

open Tls.Model

theorem pending_cases (pending : Pending)
    : pending = .none ∨ pending = .update ∨ ∃ payload, pending = .app payload := by
  cases pending <;> simp

theorem take_cons_length {α : Type} {count : Nat} {list rest : List α} {head : α}
    (taken : list.take count = head :: rest)
    : rest.length + 1 ≤ count := by
  have bound := List.length_take_le count list
  rw [taken] at bound
  simpa using bound

theorem take_cons_split {α : Type} {count : Nat} {list rest : List α} {head : α}
    (taken : list.take count = head :: rest)
    : list = head :: (rest ++ list.drop count) := by
  rw [← List.cons_append, ← taken, List.take_append_drop]

theorem schedule_spec (config : Config) (conn : Conn)
    : ∃ updateQueued misused,
        scheduleTrafficKeys config conn
          = { conn with ssl := { conn.ssl with updateQueued, misused } }
        ∧ (conn.ssl.pending = .none → misused = conn.ssl.misused)
        ∧ (conn.writeRetry = true
              ∨ conn.readWantsWrite = true
              ∨ conn.ssl.pending = .update
            → updateQueued = conn.ssl.updateQueued ∧ misused = conn.ssl.misused)
        ∧ (conn.writeRetry = false
            → conn.readWantsWrite = false
            → conn.ssl.pending = .none
            → updateQueued = false
            → conn.ssl.sent + 2 ≤ config.recordBudget)
        ∧ (updateQueued = true ∨ updateQueued = conn.ssl.updateQueued)
        ∧ (conn.ssl.sent + 2 ≤ config.recordBudget
            → updateQueued = conn.ssl.updateQueued ∧ misused = conn.ssl.misused) := by
  by_cases skip
    : (conn.writeRetry || conn.readWantsWrite || inInit conn || !updateDue config conn) = true
  · refine ⟨conn.ssl.updateQueued, conn.ssl.misused, ?_⟩
    simp only [scheduleTrafficKeys, skip, ite_true]
    simp [updateDue, inInit] at skip
    grind
  · by_cases pending : conn.ssl.pending = .none
    · refine ⟨true, conn.ssl.misused, ?_⟩
      simp only [scheduleTrafficKeys, skip, Ssl.keyUpdate, pending]
      simp [updateDue, inInit] at skip
      grind
    · refine ⟨conn.ssl.updateQueued, true, ?_⟩
      simp only [scheduleTrafficKeys, skip, Ssl.keyUpdate, pending]
      simp [updateDue, inInit] at skip
      grind

theorem refill_spec (config : Config) (ssl : Ssl) (socket : Socket)
    : ∃ input inbound,
        refill config ssl socket = ({ ssl with input }, { socket with inbound })
        ∧ (ssl.input.length ≤ config.inputBuffer → input.length ≤ config.inputBuffer)
        ∧ input ++ inbound = ssl.input ++ socket.inbound
        ∧ (ssl.input ≠ [] → input = ssl.input ∧ inbound = socket.inbound)
        ∧ (ssl.input = []
            → input = socket.inbound.take config.inputBuffer
              ∧ inbound = socket.inbound.drop config.inputBuffer) := by
  by_cases empty : ssl.input = []
  · refine ⟨socket.inbound.take config.inputBuffer, socket.inbound.drop config.inputBuffer, ?_⟩
    simp only [refill, empty, ite_true, List.take_append_drop, List.nil_append, true_and]
    refine ⟨fun _ => List.length_take_le _ _, ?_, ?_⟩ <;> simp
  · exact ⟨ssl.input, socket.inbound, by simp [refill, empty]⟩

theorem driveReady_stages (config : Config) (env : Env) (readable : Bool) (io : Io)
    : driveReady config env readable io
      = if !(prefetchStage config env readable (retryStage config env io)).conn.alive
            || readBlockedByWrite
                (prefetchStage config env readable (retryStage config env io)).conn then
          (prefetchStage config env readable (retryStage config env io), false)
        else
          writeStage
            config
            env
            (readStage config env readable
              (prefetchStage config env readable (retryStage config env io))) := by
  rfl

end Tls.Proofs
