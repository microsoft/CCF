-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import Tls.Proofs.Basic

@[expose] public section

/-!
What a worker pass does to the plaintext in flight: it neither loses, duplicates nor reorders
the plaintext it has yet to deliver, or the plaintext it has yet to send.
-/

namespace Tls.Proofs

open Tls.Model

/-- The plaintext carried by a sequence of records. -/
def payloads : List Record → List Payload
  | [] => []
  | .app payload :: rest => payload :: payloads rest
  | .keyUpdate _ :: rest => payloads rest

theorem payloads_append (first second : List Record)
    : payloads (first ++ second) = payloads first ++ payloads second := by
  induction first with
  | nil => rfl
  | cons record rest ih => cases record <;> simp [payloads, ih]

/-- A pending application record is the head of the queued output. -/
def Head (conn : Conn) : Prop :=
  ∀ payload, conn.ssl.pending = .app payload → conn.output.head? = some payload

/-- Plaintext delivered by this pass, followed by the plaintext still to be delivered. -/
def incoming (io : Io) : List Payload :=
  io.delivered.map (·.payload) ++ payloads (io.conn.ssl.input ++ io.socket.inbound)

/-- Plaintext written to the socket and not read by the peer, followed by the queued output. -/
def outgoing (io : Io) : List Payload :=
  payloads io.socket.outbound ++ io.conn.output

/-- A stage of a pass preserves the plaintext in flight in both directions. -/
def Flow (before after : Io) : Prop :=
  Head after.conn ∧ incoming after = incoming before ∧ outgoing after = outgoing before

theorem Flow.refl (io : Io) (head : Head io.conn) : Flow io io :=
  ⟨head, rfl, rfl⟩

theorem Flow.trans {first second third : Io} (early : Flow first second)
    (late : Flow second third)
    : Flow first third :=
  ⟨late.1, late.2.1.trans early.2.1, late.2.2.trans early.2.2⟩

/-- The plaintext which an `SSL_read` result delivers. -/
def deliveredBy : ReadResult → List Payload
  | .data delivery => [delivery.payload]
  | _ => []

theorem sslWrite_flow (config : Config) (env : Env) (payload : Payload) (ssl : Ssl)
    (socket : Socket) (head : ∀ pending, ssl.pending = .app pending → pending = payload)
    : (sslWrite config env payload ssl socket).2.2.inbound = socket.inbound
      ∧ (sslWrite config env payload ssl socket).2.1.input = ssl.input
      ∧ payloads (sslWrite config env payload ssl socket).2.2.outbound
        = payloads socket.outbound
          ++ (if (sslWrite config env payload ssl socket).1 = .written then
                [payload]
              else
                [])
      ∧ ∀ pending,
          (sslWrite config env payload ssl socket).2.1.pending = .app pending
          → (sslWrite config env payload ssl socket).1 ≠ .written
            ∧ pending = payload := by
  cases pending : ssl.pending
  <;> by_cases accepted : accepts config socket = true
  <;> by_cases queued : ssl.updateQueued = true
  <;> by_cases closed : env.peerClosed = true
  <;> simp [sslWrite, flushUpdate, Ssl.startUpdate, payloads_append, payloads, *]
  <;> (repeat' split)
  <;> simp_all [payloads, payloads_append]

theorem sslRead_flow (config : Config) (env : Env) (ssl : Ssl) (socket : Socket)
    : payloads (sslRead config env ssl socket).2.2.outbound = payloads socket.outbound
      ∧ deliveredBy (sslRead config env ssl socket).1
          ++ payloads
              ((sslRead config env ssl socket).2.1.input
                ++ (sslRead config env ssl socket).2.2.inbound)
        = payloads (ssl.input ++ socket.inbound)
      ∧ ∀ payload,
          (sslRead config env ssl socket).2.1.pending = .app payload
          → ssl.pending = .app payload := by
  cases pending : ssl.pending
  <;> by_cases accepted : accepts config socket = true
  <;> by_cases queued : ssl.updateQueued = true
  <;> by_cases empty : ssl.input = []
  <;> simp [sslRead, flushUpdate, refill, Ssl.startUpdate, Pending.isApp, payloads_append, *]
  <;> (repeat' split)
  <;> simp_all [payloads, deliveredBy, payloads_append]
  <;> grind [→ take_cons_split, payloads, payloads_append]

theorem doWrite_flow (config : Config) (env : Env) (io : Io) (head : Head io.conn)
    : Flow io (doWrite config env io) := by
  unfold doWrite
  split
  · exact Flow.refl io head
  · split
    · exact ⟨head, rfl, rfl⟩
    · split
      · exact ⟨head, rfl, rfl⟩
      · next payload rest output _ =>
          obtain ⟨updateQueued, misused, scheduled, _, _, _, _, _⟩ :=
            schedule_spec config io.conn
          rw [scheduled]
          have write :=
            sslWrite_flow
              config
              env
              payload
              ⟨
                io.conn.ssl.sent,
                io.conn.ssl.received,
                io.conn.ssl.pending,
                updateQueued,
                io.conn.ssl.input,
                io.conn.ssl.held,
                misused
              ⟩
              io.socket
              (by
                intro pending isPending
                have := head pending isPending
                simp_all)
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
                io.conn.ssl.held,
                misused
              ⟩
              io.socket
            = out
            at write ⊢
          obtain ⟨result, ssl, socket⟩ := out
          cases result
          <;> simp only [Flow, Head, incoming, outgoing, close] at write ⊢
          <;> grind

theorem doRead_flow (config : Config) (env : Env) (fuel : Nat) (io : Io)
    (head : Head io.conn)
    : Flow io (doRead config env fuel io).1 := by
  induction fuel generalizing io with
  | zero =>
      simp only [doRead]
      exact Flow.refl io head
  | succ fuel ih =>
      simp only [doRead]
      split
      · exact Flow.refl io head
      · have read := sslRead_flow config env io.conn.ssl io.socket
        generalize sslRead config env io.conn.ssl io.socket = out at read ⊢
        obtain ⟨result, ssl, socket⟩ := out
        cases result with
        | failed =>
            simp only [Flow, Head, incoming, outgoing, close, deliveredBy] at read head ⊢
            grind
        | wantWrite =>
            simp only [Flow, Head, incoming, outgoing, deliveredBy] at read head ⊢
            grind
        | data delivery =>
            dsimp only at read ⊢
            have next
              : Flow
                  io
                  {
                    io with
                      conn := { io.conn with ssl, readWantsWrite := false }
                      socket
                      delivered := io.delivered ++ [delivery]
                  } := by
              simp only [Flow, Head, incoming, outgoing, deliveredBy] at read head ⊢
              grind
            split
            · exact next
            · exact next.trans (ih _ next.1)
        | wantRead progressed =>
            dsimp only at read ⊢
            have next
              : Flow io { io with conn := { io.conn with ssl, readWantsWrite := false }, socket } := by
              simp only [Flow, Head, incoming, outgoing, deliveredBy] at read head ⊢
              grind
            split
            · exact next.trans (ih _ next.1)
            · exact next

theorem prefetch_flow (config : Config) (env : Env) (io : Io) (head : Head io.conn)
    : Flow io (prefetch config env io) := by
  obtain ⟨input, inbound, filled, _, joined, _, _⟩ := refill_spec config io.conn.ssl io.socket
  have next
    : Flow
        io
        {
          io with
            conn := { io.conn with ssl := { io.conn.ssl with input } }
            socket := { io.socket with inbound }
        } := by
    simp only [Flow, Head, incoming, outgoing] at head ⊢
    grind
  simp only [prefetch, filled]
  split
  · exact ⟨next.1, next.2.1, next.2.2⟩
  · exact next.trans (doWrite_flow config env _ next.1)

theorem driveReady_flow (config : Config) (env : Env) (readable : Bool) (io : Io)
    (head : Head io.conn)
    : Flow io (driveReady config env readable io).1 := by
  rw [driveReady_stages]
  have retried : Flow io (retryStage config env io) := by
    unfold retryStage
    split
    · exact doWrite_flow config env io head
    · exact Flow.refl io head
  generalize retryStage config env io = retriedIo at retried ⊢
  have fetched : Flow io (prefetchStage config env readable retriedIo) := by
    unfold prefetchStage
    split
    · exact retried.trans (prefetch_flow config env retriedIo retried.1)
    · exact retried
  generalize prefetchStage config env readable retriedIo = fetchedIo at fetched ⊢
  split
  · exact fetched
  · have read : Flow io (readStage config env readable fetchedIo).1 := by
      unfold readStage
      split
      · exact fetched.trans (doRead_flow config env _ fetchedIo fetched.1)
      · exact fetched
    generalize readStage config env readable fetchedIo = readResult at read ⊢
    unfold writeStage
    split
    · exact read.trans (doWrite_flow config env readResult.1 read.1)
    · exact read

theorem pass_flow (config : Config) (env : Env) (io next : Io) (head : Head io.conn)
    (passed : pass config env io = some next)
    : Flow io next := by
  unfold pass at passed
  dsimp only at passed
  split at passed
  · have driven := driveReady_flow config env (readableEvent env io) io head
    generalize driveReady config env (readableEvent env io) io = result at driven passed
    obtain ⟨driven, more⟩ := result
    cases passed
    exact driven
  · cases passed

end Tls.Proofs
