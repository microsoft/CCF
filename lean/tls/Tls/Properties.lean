-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import Tls.Properties.Progress
public import Tls.Properties.Stages
public import Tls.Properties.Streams
public import CCF.Execution

import Tls.Proofs.Claims
import Tls.Proofs.Witnesses

@[expose] public section

/-!
# Human-reviewed properties of the TLS connection engine model

Review these statements with the definitions in `Tls/Model/`, `Tls/Model.lean` and
`Tls/Properties/`. Each theorem links to its implementation in `Tls/Proofs/`, and is followed
by a witness that its premises can hold.

`Model.node` is one engine whose connections face arbitrary peers and owners. `Model.pair` is
two engines facing each other. `Config.Engine` is assumed throughout; `Config.Kernel` only
where stated.
-/

namespace Tls.Properties

open Tls.Model

/-! ## Safety of one connection against any peer and owner -/

/-- Key usage: no more than the budget of records is protected under one sending key, and an
open connection has decrypted no more than the budget under one receiving key. -/
theorem key_budget_respected
    : ∀ (config : Config) (state : Node.State),
        config.Engine
        → (node config).Reachable state
        → ∀ endpoint ∈ state.endpoints,
            endpoint.conn.ssl.sent ≤ config.recordBudget
            ∧ (endpoint.conn.alive = true
                → endpoint.conn.ssl.received ≤ config.recordBudget) := by
  exact Proofs.Claims.key_budget_respected

/-- Witness: the sending budget is reached, by a KeyUpdate which a full socket does not take. -/
theorem key_budget_respected_witness
    : ∃ (config : Config) (state : Node.State),
        config.Engine
        ∧ (node config).Reachable state
        ∧ ∃ endpoint ∈ state.endpoints, endpoint.conn.ssl.sent = config.recordBudget := by
  exact Proofs.Witnesses.key_budget_respected_witness

/-- Key usage: a pass delivers no plaintext from a record beyond the receive budget. -/
theorem plaintext_within_budget
    : ∀ (config : Config) (state : Node.State),
        config.Engine
        → (node config).Reachable state
        → ∀ endpoint ∈ state.endpoints,
            ∀ io,
              endpoint.pass config state.saturated = some io
              → ∀ delivery ∈ io.delivered, delivery.keyRecord ≤ config.recordBudget := by
  exact Proofs.Claims.plaintext_within_budget

/-- Witness: a pass delivers the plaintext of the last record the receive budget allows. -/
theorem plaintext_within_budget_witness
    : ∃ (config : Config) (state : Node.State) (endpoint : Node.Endpoint) (io : Io)
        (delivery : Delivery),
        config.Engine
        ∧ (node config).Reachable state
        ∧ endpoint ∈ state.endpoints
        ∧ endpoint.pass config state.saturated = some io
        ∧ delivery ∈ io.delivered
        ∧ delivery.keyRecord = config.recordBudget := by
  exact Proofs.Witnesses.plaintext_within_budget_witness

/-- OpenSSL contract: the engine never retries a write with other data, calls `SSL_key_update`
with a write pending, or calls `SSL_read` with an application write pending and a KeyUpdate
queued. `misused` records exactly these operations. -/
theorem openssl_contract_respected
    : ∀ (config : Config) (state : Node.State),
        config.Engine
        → (node config).Reachable state
        → ∀ endpoint ∈ state.endpoints, endpoint.conn.ssl.misused = false := by
  exact Proofs.Claims.openssl_contract_respected

/-- Witness: a peer can leave an open connection with an application write pending and a
KeyUpdate response owed, the state in which `SSL_read` is forbidden. -/
theorem openssl_contract_respected_witness
    : ∃ (config : Config) (state : Node.State),
        config.Engine
        ∧ (node config).Reachable state
        ∧ ∃ endpoint ∈ state.endpoints,
            endpoint.conn.alive = true
            ∧ endpoint.conn.ssl.updateQueued = true
            ∧ endpoint.conn.ssl.pending.isApp = true := by
  exact Proofs.Witnesses.openssl_contract_respected_witness

/-- Bounded memory: a connection's buffered input never exceeds the input buffer, and with the
queued output bound set its queued output never exceeds that bound. -/
theorem memory_bounded
    : ∀ (config : Config) (state : Node.State),
        config.Engine
        → (node config).Reachable state
        → ∀ endpoint ∈ state.endpoints,
            endpoint.conn.ssl.input.length ≤ config.inputBuffer
            ∧ ∀ bound,
                config.maxQueuedOutput = some bound
                → endpoint.conn.output.length ≤ bound := by
  exact Proofs.Claims.memory_bounded

/-- Witness: the queued output bound is reached. -/
theorem memory_bounded_witness
    : ∃ (config : Config) (state : Node.State),
        config.Engine
        ∧ (node config).Reachable state
        ∧ ∃ endpoint ∈ state.endpoints,
            config.maxQueuedOutput = some endpoint.conn.output.length := by
  exact Proofs.Witnesses.memory_bounded_witness

/-- Isolation: an event on one connection is a step of that connection alone, which observes
nothing of the node but inbound admission, and changes neither admission nor any other
connection. -/
theorem connections_isolated
    : ∀ (config : Config) (state next : Node.State) (index : Nat) (event : Node.Event),
        (node config).step state (.connection index event) = some next
        → next.saturated = state.saturated
          ∧ (∃ before after,
              state.endpoints[index]? = some before
              ∧ before.step config state.saturated event = some after
              ∧ next.endpoints[index]? = some after)
          ∧ ∀ other,
              other ≠ index → next.endpoints[other]? = state.endpoints[other]? := by
  exact Proofs.Claims.connections_isolated

/-- Witness: one of two connections can step. -/
theorem connections_isolated_witness
    : ∃ (config : Config) (state next : Node.State) (index : Nat) (event : Node.Event),
        (node config).step state (.connection index event) = some next
        ∧ ∃ other, other ≠ index ∧ other < state.endpoints.length := by
  exact Proofs.Witnesses.connections_isolated_witness

/-! ## Two engines on one connection -/

/-- Both ends of a connection between two engines satisfy the key budgets, the OpenSSL
contract and the memory bounds. -/
theorem engines_safe
    : ∀ (config : Config) (state : Pair.State),
        config.Engine
        → (pair config).Reachable state
        → ∀ side,
            (state.conn side).ssl.sent ≤ config.recordBudget
            ∧ ((state.conn side).alive = true
                → (state.conn side).ssl.received ≤ config.recordBudget)
            ∧ (state.conn side).ssl.misused = false
            ∧ (state.conn side).ssl.input.length ≤ config.inputBuffer
            ∧ ∀ bound,
                config.maxQueuedOutput = some bound
                → (state.conn side).output.length ≤ bound := by
  exact Proofs.Claims.engines_safe

/-- Witness: two engines exchange a record. -/
theorem engines_safe_witness
    : ∃ (config : Config) (state : Pair.State),
        config.Engine ∧ (pair config).Reachable state ∧ state.right.ssl.received = 1 := by
  exact Proofs.Witnesses.engines_safe_witness

/-- Stream integrity: along every execution, the plaintext delivered to one owner is a prefix
of the plaintext accepted from the other. -/
theorem stream_integrity
    : ∀ (config : Config) (start final : Pair.State) (actions : List Pair.Action),
        config.Engine
        → (pair config).init start
        → CCF.Execution.Run (pair config) start actions final
        → ∀ side,
            deliveredAlong config side start actions
            <+: acceptedAlong config side.peer start actions := by
  exact Proofs.Claims.stream_integrity

/-- Witness: three records are delivered in order across a KeyUpdate. -/
theorem stream_integrity_witness
    : ∃ (config : Config) (start final : Pair.State) (actions : List Pair.Action),
        config.Engine
        ∧ (pair config).init start
        ∧ CCF.Execution.Run (pair config) start actions final
        ∧ deliveredAlong config .right start actions = [1, 2, 3] := by
  exact Proofs.Witnesses.stream_integrity_witness

/-! ## Deadlock freedom and progress of two engines -/

/-- Some action is enabled in every reachable state. This is the shared definition, and holds
trivially because inbound admission may always change; `progress_enabled` is the useful claim. -/
theorem deadlock_free : ∀ (config : Config), (pair config).DeadlockFree := by
  exact Proofs.Claims.deadlock_free

/-- Witness: a state is reachable. -/
theorem deadlock_free_witness
    : ∃ (config : Config) (state : Pair.State), (pair config).Reachable state := by
  exact Proofs.Witnesses.deadlock_free_witness

/-- Progress: while both ends are open, if anything is on its way to an end whose node admits
input, then a worker pass is enabled and it consumes work. -/
theorem progress_enabled
    : ∀ (config : Config) (state : Pair.State),
        config.Engine
        → config.Kernel
        → (pair config).Reachable state
        → state.left.alive = true
        → state.right.alive = true
        → ∀ side,
            InTransit state side
            → state.saturated side = false
            → ∃ actor next,
                (pair config).step state (.pass actor) = some next
                ∧ work next < work state := by
  exact Proofs.Claims.progress_enabled

/-- Witness: the reciprocal case is reachable. Both ends have a KeyUpdate due, output queued
behind it, and a full socket. -/
theorem progress_enabled_witness
    : ∃ (config : Config) (state : Pair.State),
        config.Engine
        ∧ config.Kernel
        ∧ (pair config).Reachable state
        ∧ state.left.alive = true
        ∧ state.right.alive = true
        ∧ ∀ side,
            InTransit state side
            ∧ state.saturated side = false
            ∧ updateDue config (state.conn side) = true
            ∧ (state.conn side).output ≠ []
            ∧ accepts config (state.socket side) = false := by
  exact Proofs.Witnesses.progress_enabled_witness

/-- Every worker pass consumes work, whichever end runs it and whatever state the other end
is in. -/
theorem pass_consumes_work
    : ∀ (config : Config) (state next : Pair.State) (actor : Pair.Side),
        config.Engine
        → config.Kernel
        → (pair config).Reachable state
        → (pair config).step state (.pass actor) = some next
        → work next < work state := by
  exact Proofs.Claims.pass_consumes_work

/-- Witness: a pass is enabled in a reachable state. -/
theorem pass_consumes_work_witness
    : ∃ (config : Config) (state next : Pair.State) (actor : Pair.Side),
        config.Engine
        ∧ config.Kernel
        ∧ (pair config).Reachable state
        ∧ (pair config).step state (.pass actor) = some next := by
  exact Proofs.Witnesses.pass_consumes_work_witness

/-- Termination: the passes of any execution are bounded by the work at its start and the
work its sends add. Passes cannot continue for ever unless owners keep sending. -/
theorem passes_bounded
    : ∀ (config : Config) (start final : Pair.State) (actions : List Pair.Action),
        config.Engine
        → config.Kernel
        → (pair config).Reachable start
        → CCF.Execution.Run (pair config) start actions final
        → (actions.filter isPass).length + work final
          ≤ work start + (actions.map addedWork).sum := by
  exact Proofs.Claims.passes_bounded

/-- Witness: an execution with ten passes. -/
theorem passes_bounded_witness
    : ∃ (config : Config) (start final : Pair.State) (actions : List Pair.Action),
        config.Engine
        ∧ config.Kernel
        ∧ (pair config).Reachable start
        ∧ CCF.Execution.Run (pair config) start actions final
        ∧ (actions.filter isPass).length = 10 := by
  exact Proofs.Witnesses.passes_bounded_witness

/-- Delivery: when no pass is enabled, both ends are open and an end's node admits input,
everything accepted from the other owner has been delivered to that end's owner. -/
theorem quiescent_delivered
    : ∀ (config : Config) (start final : Pair.State) (actions : List Pair.Action),
        config.Engine
        → config.Kernel
        → (pair config).init start
        → CCF.Execution.Run (pair config) start actions final
        → final.left.alive = true
        → final.right.alive = true
        → ∀ side,
            final.saturated side = false
            → (∀ actor, (pair config).step final (.pass actor) = none)
            → deliveredAlong config side start actions
              = acceptedAlong config side.peer start actions := by
  exact Proofs.Claims.quiescent_delivered

/-- Witness: an execution accepts three records and runs until no pass is enabled. -/
theorem quiescent_delivered_witness
    : ∃ (config : Config) (start final : Pair.State) (actions : List Pair.Action),
        config.Engine
        ∧ config.Kernel
        ∧ (pair config).init start
        ∧ CCF.Execution.Run (pair config) start actions final
        ∧ final.left.alive = true
        ∧ final.right.alive = true
        ∧ final.saturated .right = false
        ∧ (∀ actor, (pair config).step final (.pass actor) = none)
        ∧ acceptedAlong config .left start actions = [1, 2, 3] := by
  exact Proofs.Witnesses.quiescent_delivered_witness

/-! ## Passes which are not atomic

Trace validation replays the engine with `interleavedPass`, in which the peer and the kernel
act between the stages of a pass. These theorems relate that to the model above.
-/

/-- An atomic pass is an interleaved pass in which nothing else acts. -/
theorem atomic_pass_interleaved
    : ∀ (config : Config) (env : Env) (io next : Io),
        pass config env io = some next
        → next
          = interleavedPass config (.atomic config env) (readableEvent env io) io := by
  exact Proofs.Claims.atomic_pass_interleaved

/-- Witness: a pass is enabled. -/
theorem atomic_pass_interleaved_witness
    : ∃ (config : Config) (env : Env) (io next : Io), pass config env io = some next := by
  exact Proofs.Witnesses.atomic_pass_interleaved_witness

/-- The key budgets, the OpenSSL contract and the memory bounds hold of every connection
reached by interleaved passes, against any peer and owner. -/
theorem replayed_connections_safe
    : ∀ (config : Config) (conn : Conn),
        config.Engine
        → Replayable config conn
        → conn.ssl.sent ≤ config.recordBudget
          ∧ (conn.alive = true → conn.ssl.received ≤ config.recordBudget)
          ∧ conn.ssl.misused = false
          ∧ conn.ssl.input.length ≤ config.inputBuffer
          ∧ ∀ bound,
              config.maxQueuedOutput = some bound → conn.output.length ≤ bound := by
  exact Proofs.Claims.replayed_connections_safe

/-- Witness: an interleaved pass reaches a connection which has read a record. -/
theorem replayed_connections_safe_witness
    : ∃ (config : Config) (conn : Conn),
        config.Engine ∧ Replayable config conn ∧ conn.ssl.received = 1 := by
  exact Proofs.Witnesses.replayed_connections_safe_witness

/-- No interleaved pass delivers plaintext from a record beyond the receive budget. -/
theorem replayed_plaintext_within_budget
    : ∀ (config : Config) (conn : Conn) (interleaving : Interleaving) (readable : Bool)
        (socket : Socket),
        config.Engine
        → Replayable config conn
        → conn.alive = true
        → ∀ delivery ∈
            (interleavedPass config interleaving readable { conn, socket }).delivered,
            delivery.keyRecord ≤ config.recordBudget := by
  exact Proofs.Claims.replayed_plaintext_within_budget

/-- Witness: an interleaved pass delivers plaintext. -/
theorem replayed_plaintext_within_budget_witness
    : ∃ (config : Config) (conn : Conn) (interleaving : Interleaving) (readable : Bool)
        (socket : Socket) (delivery : Delivery),
        config.Engine
        ∧ Replayable config conn
        ∧ conn.alive = true
        ∧ delivery
          ∈ (interleavedPass config interleaving readable
              { conn, socket }).delivered := by
  exact Proofs.Witnesses.replayed_plaintext_within_budget_witness

end Tls.Properties
