-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import Tls.Properties
public import Tls.Proofs.Execution

public section

/-!
Regression scenarios which the kernel evaluates at build time: the cases the engine's rules
were written for, and the cases which the liveness theorems deliberately do not cover.
-/

namespace Tls.Tests.Scenarios

open Tls.Model Tls.Properties Tls.Proofs

private def tight : Config :=
  {
    recordBudget := 2
    socketCapacity := 1
    writableThreshold := 1
    inputBuffer := 1
    readsPerPass := 1
    maxQueuedOutput := some 3
  }

private def alternate : Nat → List Pair.Action
  | 0 => []
  | rounds + 1 => .pass .left :: .pass .right :: alternate rounds

/-! ## The reciprocal case -/

/-- Each end writes one record while reads are held back, leaving both with a KeyUpdate due
and a full socket, then both run until nothing is left to do. -/
private def reciprocal : List Pair.Action :=
  [
    .admission .left true,
    .admission .right true,
    .send .left [1, 2, 3],
    .send .right [4, 5, 6],
    .pass .left,
    .pass .right,
    .admission .left false,
    .admission .right false
  ]
  ++ alternate 5

/-- Both directions are delivered in full, in order, across a KeyUpdate each way. -/
example
    : deliveredAlong tight .right {} reciprocal = [1, 2, 3]
      ∧ deliveredAlong tight .left {} reciprocal = [4, 5, 6] := by
  decide +kernel

/-- Both ends stay open, and no pass remains enabled. -/
example
    : (exec (pair tight) {} reciprocal).any
        (fun final =>
          final.left.alive
          && final.right.alive
          && (Pair.step tight final (.pass .left)).isNone
          && (Pair.step tight final (.pass .right)).isNone)
      = true := by
  decide +kernel

/-! ## A write beginning with a KeyUpdate waits for a writable socket -/

/-- As `tight`, with a kernel which reports a full socket as writable, so that the engine's
rule never defers a write. This kernel does not satisfy `Config.Kernel`. -/
private def eager : Config :=
  { tight with writableThreshold := 0 }

/-- The left end writes the one record its socket holds, then a second pass is attempted with
a KeyUpdate due. The right end reads nothing. -/
private def updateOnFullSocket : List Pair.Action :=
  [.admission .right true, .send .left [1, 2], .pass .left, .pass .left]

/-- With the modelled kernel the full socket does not poll writable, so the second pass is
not scheduled and no KeyUpdate is started. -/
example : exec (pair tight) {} updateOnFullSocket = none := by
  decide +kernel

/-- Up to that pass the left end is not in init, and it can still read. -/
example
    : (exec (pair tight) {} (updateOnFullSocket.take 3)).any
        (fun state => !inInit state.left && !readBlockedByWrite state.left)
      = true := by
  decide +kernel

/-- With the eager kernel the write is started: the KeyUpdate is constructed, cannot be
flushed, and blocks the left end's reads until the right end drains the socket. -/
example
    : (exec (pair eager) {} updateOnFullSocket).any
        (fun state => inInit state.left && readBlockedByWrite state.left)
      = true := by
  decide +kernel

/-! ## A stalled state which two engines cannot reach -/

/-- A kernel whose sockets hold three records and poll writable with two free, and an input
buffer of one record: draining a full input buffer does not make the peer's socket writable. -/
private def narrow : Config :=
  {
    recordBudget := 4
    socketCapacity := 3
    writableThreshold := 2
    inputBuffer := 1
    readsPerPass := 1
    maxQueuedOutput := none
  }

/-- An end which started a KeyUpdate on a full socket, and then prefetched one record. -/
private def started (payload : Payload) : Conn :=
  {
    ssl := { sent := 4, pending := .update, input := [.app payload] }
    output := [payload + 1]
    queued := 1
    writeRetry := true
    wantWrite := true
    readPaused := true
  }

/--
Both ends have started a KeyUpdate. Each has drained what its input buffer holds, so each
socket has one record free: enough for the peer's KeyUpdate, but not enough to poll writable.

The state is written out, not reached. The model's passes are atomic and its sockets take
effect at once, so nothing here establishes whether engines which started such writes on
unwritable sockets could arrive at it.
-/
private def stalled : Pair.State :=
  {
    left := started 10
    right := started 20
    toRight := [.app 11, .app 12]
    toLeft := [.app 21, .app 22]
  }

/-- No pass is enabled although both ends are open, both have input waiting, and each socket
would accept the other end's KeyUpdate. -/
example
    : Pair.step narrow stalled (.pass .left) = none
      ∧ Pair.step narrow stalled (.pass .right) = none
      ∧ stalled.left.alive = true
      ∧ stalled.right.alive = true
      ∧ accepts narrow (stalled.socket .left) = true
      ∧ accepts narrow (stalled.socket .right) = true := by
  decide +kernel

/-- Two engines cannot reach that state, because `progress_enabled` would enable a pass. -/
example : ¬(pair narrow).Reachable stalled := by
  intro reachable
  have engine : narrow.Engine := by
    unfold Config.Engine
    decide
  have kernel : narrow.Kernel := by
    unfold Config.Kernel
    decide
  have transit : InTransit stalled .left := by
    unfold InTransit
    decide
  obtain ⟨actor, next, stepped, _⟩ :=
    progress_enabled narrow stalled engine kernel reachable rfl rfl .left transit rfl
  have disabled : (pair narrow).step stalled (.pass actor) = none := by
    cases actor <;> decide +kernel
  rw [disabled] at stepped
  cases stepped

/-! ## The queued output bound -/

/-- A peer which does not read: the owner fills the bound, and the next send closes the
connection with its output unwritten. -/
private def overfilled : List Node.Action :=
  [.accept, .connection 0 (.send [1, 2, 3]), .connection 0 (.send [4])]

example
    : (exec (node tight) {} overfilled).any
        (fun state =>
          state.endpoints.all
            fun endpoint =>
              !endpoint.conn.alive
              && endpoint.conn.output.length == 3
              && endpoint.socket.outbound.isEmpty)
      = true := by
  decide +kernel

/-- A closed connection accepts nothing more. -/
example : exec (node tight) {} (overfilled ++ [.connection 0 (.send [5])]) = none := by
  decide +kernel

/-! ## Not claimed: a peer which requests KeyUpdates and does not read -/

/-- A budget of three records, so that the second write is not preceded by a KeyUpdate. -/
private def wide : Config :=
  { tight with recordBudget := 3 }

/--
The engine has an application write pending on a full socket when its peer requests a
KeyUpdate and sends two more records without reading anything.
-/
private def silentRequester : List Node.Action :=
  [
    .accept,
    .connection 0 (.send [1, 2]),
    .connection 0 .pass,
    .connection 0 (.send []),
    .connection 0 .pass,
    .connection 0 (.peerSend (.keyUpdate true)),
    .connection 0 .pass,
    .connection 0 (.peerSend (.app 9)),
    .connection 0 (.peerSend (.app 10)),
    .connection 0 .pass
  ]

/-- The connection stays open and within its memory bounds, but reads are withheld and no
pass is enabled: the engine waits for the peer. -/
example
    : (exec (node wide) {} silentRequester).any
        (fun state =>
          state.endpoints.all
            fun endpoint =>
              endpoint.conn.alive
              && endpoint.conn.readPaused
              && endpoint.conn.ssl.input.length == 1
              && endpoint.socket.inbound.length == 1
              && (endpoint.step wide state.saturated .pass).isNone)
      = true := by
  decide +kernel

/-- Once the peer reads a record, a pass is enabled again. -/
example
    : exec (node wide) {}
        (silentRequester ++ [.connection 0 .peerReceive, .connection 0 .pass])
      ≠ none := by
  decide +kernel

/-! ## The modelled OpenSSL contract can be broken -/

private def quietEnv : Env :=
  { saturated := false, peerClosed := false }

/-- `SSL_key_update` with a write pending is flagged. -/
example : ({ pending := .app 1 } : Ssl).keyUpdate.misused = true := by
  decide

/-- A write retried with other data is flagged. -/
example : (sslWrite tight quietEnv 2 { pending := .app 1 } {}).2.1.misused = true := by
  decide +kernel

/-- `SSL_read` with an application write pending and a KeyUpdate queued is flagged. -/
example
    : (sslRead tight quietEnv { pending := .app 1, updateQueued := true } {}).2.1.misused
      = true := by
  decide +kernel

end Tls.Tests.Scenarios
