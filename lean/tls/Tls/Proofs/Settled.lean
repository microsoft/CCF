-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import Tls.Proofs.Quiet

@[expose] public section

/-!
The engine's operations on a connection whose peer never requests a KeyUpdate: each keeps the
connection quiet and does not add to the work measure.
-/

namespace Tls.Proofs

open Tls.Model Tls.Properties

theorem doWrite_pair (config : Config) (env : Env) (io : Io) (kernel : config.Kernel)
    (coherent : Coherent config io.conn) (alive : io.conn.alive = true)
    (quiet : Quiet io.conn) (unrequested : .keyUpdate true ∉ io.socket.outbound)
    : ((doWrite config env io).conn.alive = true → Quiet (doWrite config env io).conn)
      ∧ .keyUpdate true ∉ (doWrite config env io).socket.outbound
      ∧ (doWrite config env io).conn.ssl.input = io.conn.ssl.input
      ∧ (doWrite config env io).socket.inbound = io.socket.inbound
      ∧ (doWrite config env io).conn.pendingRead = io.conn.pendingRead
      ∧ (doWrite config env io).conn.dirty = io.conn.dirty
      ∧ (doWrite config env io).conn.readPaused = io.conn.readPaused
      ∧ ((doWrite config env io).conn.alive = true
          → ((doWrite config env io).conn.output = []
              → (doWrite config env io).conn.wantWrite = false)
            ∧ ((doWrite config env io).conn.output ≠ []
                → (doWrite config env io).conn.wantWrite = true))
      ∧ ((doWrite config env io).conn.alive = false
          → (doWrite config env io).conn.output = io.conn.output
            ∧ (doWrite config env io).conn.wantWrite = io.conn.wantWrite)
      ∧ writeWork (doWrite config env io) ≤ writeWork io
      ∧ ((doWrite config env io).conn.alive = true
          → io.conn.output ≠ []
          → pollsWritable config io.socket = true ∨ env.peerClosed = true
          → writeWork (doWrite config env io) < writeWork io) := by
  obtain ⟨_, _, _, _, _, _, _, _, pendingApp, _, _, _⟩ := coherent
  obtain ⟨notQueued, notInit, notReadBlocked⟩ := quiet
  have pending := pending_cases io.conn.ssl.pending
  unfold doWrite
  split
  · simp_all
  · split
    · next output =>
        simp only [writeWork, output]
        refine ⟨fun _ => ⟨notQueued, notInit, notReadBlocked⟩, unrequested, ?_⟩
        simp [alive]
    · split
      · next payload rest output awaits =>
          simp only [writeWork, output]
          refine ⟨fun _ => ⟨notQueued, notInit, notReadBlocked⟩, unrequested, ?_⟩
          simp [updateAwaitsSocket] at awaits
          simp
          grind
      · next payload rest output awaits =>
          obtain ⟨updateQueued, misused, scheduled, _, s2, _, _, s5⟩ :=
            schedule_spec config io.conn
          rw [scheduled]
          have accepted
              : pollsWritable config io.socket = true
                → accepts config io.socket = true := by
            have := kernel.1
            simp only [pollsWritable, accepts, decide_eq_true_eq]
            omega
          have room
            : updateQueued = true → accepts config io.socket = true ∨ env.peerClosed = true := by
            intro queued
            simp [updateAwaitsSocket, updateDue, inInit] at awaits
            grind
          have write :=
            sslWrite_pair
              config
              env
              payload
              ⟨
                io.conn.ssl.sent,
                io.conn.ssl.received,
                io.conn.ssl.pending,
                updateQueued,
                io.conn.ssl.input,
                misused
              ⟩
              io.socket
              notInit
              (by grind)
              room
              unrequested
          dsimp only at write ⊢
          generalize
            sslWrite
              config
              env
              payload
              ⟨
                io.conn.ssl.sent,
                io.conn.ssl.received,
                io.conn.ssl.pending,
                updateQueued,
                io.conn.ssl.input,
                misused
              ⟩
              io.socket
            = out
            at write ⊢
          obtain ⟨result, ssl, socket⟩ := out
          cases result
          <;> simp only [close, writeWork, output] at write ⊢
          <;> refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
          <;> grind [Pending.isApp, Quiet]

/-- What `doRead` does to a quiet connection. -/
structure ReadOutcome (env : Env) (fuel : Nat) (io : Io) (result : Io × Bool) : Prop where
  /-- The connection stays quiet. -/
  quiet : result.1.conn.alive = true → Quiet result.1.conn
  /-- No requested KeyUpdate appears in the input. -/
  unrequested : .keyUpdate true ∉ result.1.conn.ssl.input ++ result.1.socket.inbound
  /-- The queued output is unchanged. -/
  output : result.1.conn.output = io.conn.output
  /-- Nothing is written. -/
  outbound : result.1.socket.outbound = io.socket.outbound
  /-- `wantWrite` is unchanged. -/
  wantWrite : result.1.conn.wantWrite = io.conn.wantWrite
  /-- `pendingRead` is unchanged. -/
  pendingRead : result.1.conn.pendingRead = io.conn.pendingRead
  /-- `dirty` is unchanged. -/
  dirty : result.1.conn.dirty = io.conn.dirty
  /-- `writeRetry` is unchanged. -/
  writeRetry : result.1.conn.writeRetry = io.conn.writeRetry
  /-- `readPaused` is unchanged. -/
  readPaused : result.1.conn.readPaused = io.conn.readPaused
  /-- The pending write is unchanged. -/
  pending : result.1.conn.ssl.pending = io.conn.ssl.pending
  /-- Reading does not add work. -/
  work : readWork result.1 ≤ readWork io
  /-- `more_to_read` is reported only with input buffered. -/
  more : result.2 = true → result.1.conn.ssl.input ≠ []
  /-- Nothing is read while admission is saturated. -/
  saturated
    : env.saturated = true
      → result.1.conn.ssl.input = io.conn.ssl.input
        ∧ result.1.socket.inbound = io.socket.inbound
        ∧ result.1.conn.alive = true
  /-- Otherwise a record is consumed, unless there is none. -/
  progress
    : env.saturated = false → fuel ≠ 0 → result.1.conn.alive = true
      → readWork result.1 < readWork io
        ∨ (io.conn.ssl.input = [] ∧ io.socket.inbound = [] ∧ env.peerClosed = false)

theorem doRead_pair (config : Config) (env : Env) (engine : config.Engine) (fuel : Nat)
    (io : Io) (alive : io.conn.alive = true) (quiet : Quiet io.conn)
    (unrequested : .keyUpdate true ∉ io.conn.ssl.input ++ io.socket.inbound)
    : ReadOutcome env fuel io (doRead config env fuel io) := by
  induction fuel generalizing io with
  | zero =>
      simp only [doRead]
      constructor <;> simp_all [hasInput]
  | succ fuel ih =>
      simp only [doRead]
      split
      · constructor <;> simp_all [hasInput]
      · next unsaturated =>
          obtain ⟨notQueued, notInit, _⟩ := quiet
          have read :=
            sslRead_pair config env io.conn.ssl io.socket engine.2.1 notInit notQueued unrequested
          generalize sslRead config env io.conn.ssl io.socket = out at read ⊢
          obtain ⟨result, ssl, socket⟩ := out
          cases result with
          | failed =>
              simp only [close] at read ⊢
              constructor <;> grind [Quiet, readWork, hasInput]
          | wantWrite => simp at read
          | data delivery =>
              dsimp only at read ⊢
              split
              · simp only [hasInput] at read ⊢
                constructor <;> grind [Quiet, readWork, hasInput]
              · obtain ⟨q, u, o, ob, ww, pr, d, wr, rp, p, w, m, _, _⟩ :=
                  ih
                    {
                      io with
                        conn := { io.conn with ssl, readWantsWrite := false }
                        socket
                        delivered := io.delivered ++ [delivery]
                    }
                    alive
                    ⟨read.2.1, by simp only [read.1]; exact notInit, rfl⟩
                    read.2.2.2.2.1
                constructor <;> grind [Quiet, readWork, hasInput]
          | wantRead progressed =>
              dsimp only at read ⊢
              split
              · next continuing =>
                  obtain ⟨q, u, o, ob, ww, pr, d, wr, rp, p, w, m, _, _⟩ :=
                    ih
                      { io with conn := { io.conn with ssl, readWantsWrite := false }, socket }
                      alive
                      ⟨read.2.1, by simp only [read.1]; exact notInit, rfl⟩
                      read.2.2.2.2.1
                  simp at continuing
                  constructor <;> grind [Quiet, readWork, hasInput]
              · next stopping =>
                  simp [readBlockedByWrite, inInit, hasInput] at stopping
                  constructor <;> grind [Quiet, readWork, hasInput]

end Tls.Proofs
