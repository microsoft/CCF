-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import Tls.Proofs.Execution
public import Tls.Properties.Progress
public import Tls.Properties.Streams

@[expose] public section

/-!
Concrete executions which show that the premises of the public theorems can hold, and that
their bounds are attained. The kernel evaluates each execution.
-/

namespace Tls.Proofs.Witnesses

open Tls.Model Tls.Properties

/-- A budget of two records, single-record buffers, and a bound of three queued records. -/
def tight : Config :=
  {
    recordBudget := 2
    socketCapacity := 1
    writableThreshold := 1
    inputBuffer := 1
    readsPerPass := 1
    maxQueuedOutput := some 3
  }

/-- As `tight`, with a kernel which reports a full socket as writable. -/
def eager : Config :=
  { tight with writableThreshold := 0 }

/-- As `eager`, with a budget of three records. -/
def roomy : Config :=
  { eager with recordBudget := 3 }

theorem tight_engine : tight.Engine := by
  unfold Config.Engine
  decide

theorem eager_engine : eager.Engine := by
  unfold Config.Engine
  decide

theorem roomy_engine : roomy.Engine := by
  unfold Config.Engine
  decide

theorem tight_kernel : tight.Kernel := by
  unfold Config.Kernel
  decide

/-- The node state a list of actions reaches. -/
def nodeAfter (config : Config) (actions : List Node.Action) : Node.State :=
  execD (node config) {} actions

/-- The state of two engines which a list of actions reaches. -/
def pairAfter (config : Config) (actions : List Pair.Action) : Pair.State :=
  execD (pair config) {} actions

/-- A sender writes a record, then starts a KeyUpdate which the full socket does not take. -/
def budgetReached : List Node.Action :=
  [.accept, .connection 0 (.send [1, 2]), .connection 0 .pass, .connection 0 .pass]

theorem key_budget_respected_witness
    : ∃ (config : Config) (state : Node.State),
        config.Engine
        ∧ (node config).Reachable state
        ∧ ∃ endpoint ∈ state.endpoints, endpoint.conn.ssl.sent = config.recordBudget :=
  ⟨
    eager,
    nodeAfter eager budgetReached,
    eager_engine,
    execD_reachable _ _ _ (.initial rfl) (by decide +kernel),
    by decide +kernel
  ⟩

/-- A peer sends two records under one key; the second is about to be read. -/
def lastRecordOfKey : List Node.Action :=
  [
    .accept,
    .connection 0 (.peerSend (.app 7)),
    .connection 0 .pass,
    .connection 0 (.peerSend (.app 8))
  ]

theorem plaintext_within_budget_witness
    : ∃ (config : Config) (state : Node.State) (endpoint : Node.Endpoint) (io : Io)
        (delivery : Delivery),
        config.Engine
        ∧ (node config).Reachable state
        ∧ endpoint ∈ state.endpoints
        ∧ endpoint.pass config state.saturated = some io
        ∧ delivery ∈ io.delivered
        ∧ delivery.keyRecord = config.recordBudget :=
  ⟨
    tight,
    nodeAfter tight lastRecordOfKey,
    (nodeAfter tight lastRecordOfKey).endpoints.headD {},
    (((nodeAfter tight lastRecordOfKey).endpoints.headD {}).pass tight false).getD
      { conn := {}, socket := {} },
    { payload := 8, keyRecord := 2 },
    tight_engine,
    execD_reachable _ _ _ (.initial rfl) (by decide +kernel),
    by decide +kernel,
    by decide +kernel,
    by decide +kernel,
    rfl
  ⟩

/-- A peer requests a KeyUpdate while the engine has an application write pending. -/
def responseOwedBehindWrite : List Node.Action :=
  [
    .accept,
    .connection 0 (.send [1, 2]),
    .connection 0 .pass,
    .connection 0 .pass,
    .connection 0 (.peerSend (.keyUpdate true)),
    .connection 0 .pass
  ]

theorem openssl_contract_respected_witness
    : ∃ (config : Config) (state : Node.State),
        config.Engine
        ∧ (node config).Reachable state
        ∧ ∃ endpoint ∈ state.endpoints,
            endpoint.conn.alive = true
            ∧ endpoint.conn.ssl.updateQueued = true
            ∧ endpoint.conn.ssl.pending.isApp = true :=
  ⟨
    roomy,
    nodeAfter roomy responseOwedBehindWrite,
    roomy_engine,
    execD_reachable _ _ _ (.initial rfl) (by decide +kernel),
    by decide +kernel
  ⟩

/-- An owner fills the queued output bound of a connection whose socket has not been tried. -/
def boundReached : List Node.Action :=
  [.accept, .connection 0 (.send [1, 2, 3])]

theorem memory_bounded_witness
    : ∃ (config : Config) (state : Node.State),
        config.Engine
        ∧ (node config).Reachable state
        ∧ ∃ endpoint ∈ state.endpoints,
            config.maxQueuedOutput = some endpoint.conn.output.length :=
  ⟨
    tight,
    nodeAfter tight boundReached,
    tight_engine,
    execD_reachable _ _ _ (.initial rfl) (by decide +kernel),
    by decide +kernel
  ⟩

theorem connections_isolated_witness
    : ∃ (config : Config) (state next : Node.State) (index : Nat) (event : Node.Event),
        (node config).step state (.connection index event) = some next
        ∧ ∃ other, other ≠ index ∧ other < state.endpoints.length :=
  ⟨
    tight,
    nodeAfter tight [.accept, .accept],
    nodeAfter tight [.accept, .accept, .connection 0 (.send [1])],
    0,
    .send [1],
    by decide +kernel,
    1,
    by decide,
    by decide +kernel
  ⟩

/-- One record is sent and received. -/
def oneRecord : List Pair.Action :=
  [.send .left [1], .pass .left, .pass .right]

theorem engines_safe_witness
    : ∃ (config : Config) (state : Pair.State),
        config.Engine ∧ (pair config).Reachable state ∧ state.right.ssl.received = 1 :=
  ⟨
    tight,
    pairAfter tight oneRecord,
    tight_engine,
    execD_reachable _ _ _ (.initial rfl) (by decide +kernel),
    by decide +kernel
  ⟩

/-- Passes at alternate ends, starting at the left. -/
def alternate : Nat → List Pair.Action
  | 0 => []
  | rounds + 1 => .pass .left :: .pass .right :: alternate rounds

/-- Three records are sent in one direction, across a KeyUpdate, until nothing is left to do. -/
def threeRecords : List Pair.Action :=
  .send .left [1, 2, 3] :: alternate 5

theorem stream_integrity_witness
    : ∃ (config : Config) (start final : Pair.State) (actions : List Pair.Action),
        config.Engine
        ∧ (pair config).init start
        ∧ CCF.Execution.Run (pair config) start actions final
        ∧ deliveredAlong config .right start actions = [1, 2, 3] :=
  ⟨
    tight,
    {},
    pairAfter tight threeRecords,
    threeRecords,
    tight_engine,
    rfl,
    execD_run _ _ _ (by decide +kernel),
    by decide +kernel
  ⟩

theorem deadlock_free_witness
    : ∃ (config : Config) (state : Pair.State), (pair config).Reachable state :=
  ⟨tight, {}, .initial rfl⟩

/--
The reciprocal case: with reads held back by admission, each end writes one record, leaving
both with a KeyUpdate due, more output queued, and a full socket. Admission then reopens.
-/
def reciprocal : List Pair.Action :=
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
            ∧ accepts config (state.socket side) = false :=
  ⟨
    tight,
    pairAfter tight reciprocal,
    tight_engine,
    tight_kernel,
    execD_reachable _ _ _ (.initial rfl) (by decide +kernel),
    by decide +kernel,
    by decide +kernel,
    fun side => by cases side <;> (unfold InTransit; decide +kernel)
  ⟩

theorem pass_consumes_work_witness
    : ∃ (config : Config) (state next : Pair.State) (actor : Pair.Side),
        config.Engine
        ∧ config.Kernel
        ∧ (pair config).Reachable state
        ∧ (pair config).step state (.pass actor) = some next :=
  ⟨
    tight,
    pairAfter tight [.send .left [1]],
    pairAfter tight [.send .left [1], .pass .left],
    .left,
    tight_engine,
    tight_kernel,
    execD_reachable _ _ _ (.initial rfl) (by decide +kernel),
    by decide +kernel
  ⟩

theorem passes_bounded_witness
    : ∃ (config : Config) (start final : Pair.State) (actions : List Pair.Action),
        config.Engine
        ∧ config.Kernel
        ∧ (pair config).Reachable start
        ∧ CCF.Execution.Run (pair config) start actions final
        ∧ (actions.filter isPass).length = 10 :=
  ⟨
    tight,
    {},
    pairAfter tight threeRecords,
    threeRecords,
    tight_engine,
    tight_kernel,
    .initial rfl,
    execD_run _ _ _ (by decide +kernel),
    by decide +kernel
  ⟩

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
        ∧ acceptedAlong config .left start actions = [1, 2, 3] :=
  ⟨
    tight,
    {},
    pairAfter tight threeRecords,
    threeRecords,
    tight_engine,
    tight_kernel,
    rfl,
    execD_run _ _ _ (by decide +kernel),
    by decide +kernel,
    by decide +kernel,
    by decide +kernel,
    fun actor => by cases actor <;> decide +kernel,
    by decide +kernel
  ⟩

end Tls.Proofs.Witnesses
