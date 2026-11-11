-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import Tls.Proofs.Local
public import Tls.Properties.Progress

@[expose] public section

/-!
A connection whose peer never requests a KeyUpdate, on a socket which satisfies the kernel
assumptions: its KeyUpdates never block, its reads are never held behind a write, and every
pass consumes work.
-/

namespace Tls.Proofs

open Tls.Model Tls.Properties

/-- No KeyUpdate is queued, constructed, or blocking a read. -/
structure Quiet (conn : Conn) : Prop where
  /-- No KeyUpdate is scheduled or owed. -/
  notQueued : conn.ssl.updateQueued = false
  /-- No KeyUpdate is constructed and unflushed. -/
  notInit : conn.ssl.pending ≠ .update
  /-- No read is blocked on a write. -/
  notReadBlocked : conn.readWantsWrite = false

/-- The part of the work measure which writing consumes. -/
def writeWork (io : Io) : Nat :=
  6 * io.conn.output.length
  + (if io.conn.ssl.pending.isApp then 0 else 3)
  + 2 * io.socket.outbound.length

/-- The part of the work measure which reading consumes. -/
def readWork (io : Io) : Nat :=
  io.conn.ssl.input.length + 2 * io.socket.inbound.length

theorem sslWrite_pair (config : Config) (env : Env) (payload : Payload) (ssl : Ssl)
    (socket : Socket) (notInit : ssl.pending ≠ .update)
    (notQueued : ssl.pending ≠ .none → ssl.updateQueued = false)
    (room
      : ssl.updateQueued = true → accepts config socket = true ∨ env.peerClosed = true)
    (unrequested : .keyUpdate true ∉ socket.outbound)
    : ((sslWrite config env payload ssl socket).1 ≠ .failed
        → (sslWrite config env payload ssl socket).2.1.pending ≠ .update
          ∧ (sslWrite config env payload ssl socket).2.1.updateQueued = false)
      ∧ .keyUpdate true ∉ (sslWrite config env payload ssl socket).2.2.outbound
      ∧ ((sslWrite config env payload ssl socket).1 = .written
          → (sslWrite config env payload ssl socket).2.1.pending = .none
            ∧ (sslWrite config env payload ssl socket).2.2.outbound.length
              ≤ socket.outbound.length + (if ssl.pending.isApp then 1 else 2))
      ∧ ((sslWrite config env payload ssl socket).1 = .wantWrite
          → (∃ pending,
              (sslWrite config env payload ssl socket).2.1.pending = .app pending)
            ∧ (ssl.pending.isApp = true
                → (sslWrite config env payload ssl socket).2.2.outbound = socket.outbound)
            ∧ (ssl.pending.isApp = false
                → (sslWrite config env payload ssl socket).2.2.outbound.length
                  ≤ socket.outbound.length + 1))
      ∧ ((sslWrite config env payload ssl socket).1 = .failed
          → (sslWrite config env payload ssl socket).2.1 = ssl
            ∧ (sslWrite config env payload ssl socket).2.2 = socket)
      ∧ (ssl.pending.isApp = true
          → accepts config socket = true
          → (sslWrite config env payload ssl socket).1 ≠ .wantWrite)
      ∧ (env.peerClosed = true → (sslWrite config env payload ssl socket).1 = .failed)
      ∧ (sslWrite config env payload ssl socket).2.1.input = ssl.input
      ∧ (sslWrite config env payload ssl socket).2.2.inbound = socket.inbound := by
  cases pending : ssl.pending
  <;> by_cases accepted : accepts config socket = true
  <;> by_cases queued : ssl.updateQueued = true
  <;> by_cases closed : env.peerClosed = true
  <;> simp [sslWrite, flushUpdate, Ssl.startUpdate, Pending.isApp, *] at notInit notQueued room ⊢
  <;> (repeat' split)
  <;> simp_all

theorem sslRead_pair (config : Config) (env : Env) (ssl : Ssl) (socket : Socket)
    (buffer : 0 < config.inputBuffer) (notInit : ssl.pending ≠ .update)
    (notQueued : ssl.updateQueued = false)
    (unrequested : .keyUpdate true ∉ ssl.input ++ socket.inbound)
    : (sslRead config env ssl socket).2.1.pending = ssl.pending
      ∧ (sslRead config env ssl socket).2.1.updateQueued = false
      ∧ (sslRead config env ssl socket).2.2.outbound = socket.outbound
      ∧ (sslRead config env ssl socket).1 ≠ .wantWrite
      ∧ .keyUpdate true
        ∉ (sslRead config env ssl socket).2.1.input
          ++ (sslRead config env ssl socket).2.2.inbound
      ∧ (sslRead config env ssl socket).2.1.input.length
          + 2 * (sslRead config env ssl socket).2.2.inbound.length
        ≤ ssl.input.length + 2 * socket.inbound.length
      ∧ ((sslRead config env ssl socket).1 = .wantRead false
          → ssl.input = [] ∧ socket.inbound = [] ∧ env.peerClosed = false)
      ∧ ((sslRead config env ssl socket).1 ≠ .failed
          → (sslRead config env ssl socket).1 ≠ .wantRead false
          → (sslRead config env ssl socket).2.1.input.length
              + 2 * (sslRead config env ssl socket).2.2.inbound.length
            < ssl.input.length + 2 * socket.inbound.length) := by
  have split := List.take_append_drop config.inputBuffer socket.inbound
  have taken := List.length_take_le config.inputBuffer socket.inbound
  cases pending : ssl.pending
  <;> by_cases accepted : accepts config socket = true
  <;> by_cases empty : ssl.input = []
  <;> simp [sslRead, flushUpdate, refill, Ssl.startUpdate, Pending.isApp, *] at notInit unrequested ⊢
  <;> (repeat' split)
  <;> simp_all
  <;> grind [→ take_cons_split]

end Tls.Proofs
