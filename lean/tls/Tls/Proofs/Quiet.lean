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
  obtain ⟨input, inbound, filled, -, joined, kept, fetched⟩ := refill_spec config ssl socket
  have measure
    : input.length + 2 * inbound.length ≤ ssl.input.length + 2 * socket.inbound.length := by
    by_cases empty : ssl.input = []
    · obtain ⟨rfl, rfl⟩ := fetched empty
      simp only [empty, List.length_take, List.length_drop, List.length_nil]
      omega
    · obtain ⟨rfl, rfl⟩ := kept empty
      exact Nat.le_refl _
  have drained : input = [] → ssl.input = [] ∧ socket.inbound = [] := by
    intro none
    by_cases empty : ssl.input = []
    · refine ⟨empty, ?_⟩
      have taken := (fetched empty).1
      rw [none] at taken
      rcases List.take_eq_nil_iff.mp taken.symm with zero | gone
      · omega
      · exact gone
    · exact absurd ((kept empty).1.symm.trans none) empty
  have absent : .keyUpdate true ∉ input ++ inbound := by
    rw [joined]
    exact unrequested
  clear joined kept fetched unrequested buffer
  simp only [sslRead, flushUpdate, notQueued, notInit, filled, Bool.false_eq_true, false_and,
    ite_false]
  clear filled
  cases input with
  | nil =>
      obtain ⟨noInput, noInbound⟩ := drained rfl
      clear drained
      cases closed : env.peerClosed <;> simp [noInput, noInbound] at measure absent ⊢
      <;> grind
  | cons record rest =>
      clear drained
      simp only [List.length_cons] at measure
      cases record with
      | app payload =>
          by_cases held : ssl.held = true
          <;> by_cases within : config.recordBudget < ssl.received + 1
          <;> by_cases same : config.recordBudget < ssl.received
          <;> simp [held, within, same] at absent ⊢
          <;> grind
      | keyUpdate requested =>
          have unasked : requested = false := by
            cases requested
            · rfl
            · simp at absent
          subst unasked
          by_cases held : ssl.held = true
          <;> by_cases within : config.recordBudget < ssl.received + 1
          <;> by_cases same : config.recordBudget < ssl.received
          <;> simp [held, within, same] at absent ⊢
          <;> grind

end Tls.Proofs
