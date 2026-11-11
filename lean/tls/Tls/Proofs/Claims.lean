-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import Tls.Proofs.Node
public import Tls.Proofs.Pair

@[expose] public section

/-! The implementations of the public theorems, in the form in which they are stated. -/

namespace Tls.Proofs.Claims

open Tls.Model Tls.Properties

theorem key_budget_respected (config : Config) (state : Node.State)
    (engine : config.Engine) (reachable : (node config).Reachable state)
    : ∀ endpoint ∈ state.endpoints,
        endpoint.conn.ssl.sent ≤ config.recordBudget
        ∧ (endpoint.conn.alive = true
            → endpoint.conn.ssl.received ≤ config.recordBudget) :=
  fun endpoint member =>
    have coherent := node_coherent config engine state reachable endpoint member
    ⟨coherent.sent, coherent.received⟩

theorem plaintext_within_budget (config : Config) (state : Node.State)
    (engine : config.Engine) (reachable : (node config).Reachable state)
    : ∀ endpoint ∈ state.endpoints,
        ∀ io,
          endpoint.pass config state.saturated = some io
          → ∀ delivery ∈ io.delivered, delivery.keyRecord ≤ config.recordBudget :=
  fun endpoint member io passed =>
    (pass_local
      config
      _
      _
      io
      engine
      (node_coherent config engine state reachable endpoint member)
      (fun _ absent => by simp at absent)
      passed).2

theorem openssl_contract_respected (config : Config) (state : Node.State)
    (engine : config.Engine) (reachable : (node config).Reachable state)
    : ∀ endpoint ∈ state.endpoints, endpoint.conn.ssl.misused = false :=
  fun endpoint member =>
    (node_coherent config engine state reachable endpoint member).notMisused

theorem memory_bounded (config : Config) (state : Node.State) (engine : config.Engine)
    (reachable : (node config).Reachable state)
    : ∀ endpoint ∈ state.endpoints,
        endpoint.conn.ssl.input.length ≤ config.inputBuffer
        ∧ ∀ bound,
            config.maxQueuedOutput = some bound → endpoint.conn.output.length ≤ bound :=
  fun endpoint member =>
    have coherent := node_coherent config engine state reachable endpoint member
    ⟨
      coherent.input,
      fun bound configured =>
        Nat.le_trans coherent.queued (coherent.bound bound configured)
    ⟩

theorem connections_isolated (config : Config) (state next : Node.State) (index : Nat)
    (event : Node.Event)
    (stepped : (node config).step state (.connection index event) = some next)
    : next.saturated = state.saturated
      ∧ (∃ before after,
          state.endpoints[index]? = some before
          ∧ before.step config state.saturated event = some after
          ∧ next.endpoints[index]? = some after)
      ∧ ∀ other, other ≠ index → next.endpoints[other]? = state.endpoints[other]? :=
  Tls.Proofs.connections_isolated config state next index event stepped

theorem engines_safe (config : Config) (state : Pair.State) (engine : config.Engine)
    (reachable : (pair config).Reachable state)
    : ∀ side,
        (state.conn side).ssl.sent ≤ config.recordBudget
        ∧ ((state.conn side).alive = true
            → (state.conn side).ssl.received ≤ config.recordBudget)
        ∧ (state.conn side).ssl.misused = false
        ∧ (state.conn side).ssl.input.length ≤ config.inputBuffer
        ∧ ∀ bound,
            config.maxQueuedOutput = some bound
            → (state.conn side).output.length ≤ bound :=
  fun side =>
    have coherent := pair_coherent config engine state reachable side
    ⟨
      coherent.sent,
      coherent.received,
      coherent.notMisused,
      coherent.input,
      fun bound configured =>
        Nat.le_trans coherent.queued (coherent.bound bound configured)
    ⟩

theorem stream_integrity (config : Config) (start final : Pair.State)
    (actions : List Pair.Action) (engine : config.Engine)
    (initial : (pair config).init start)
    (run : CCF.Execution.Run (pair config) start actions final)
    : ∀ side,
        deliveredAlong config side start actions
        <+: acceptedAlong config side.peer start actions := by
  cases initial
  exact Tls.Proofs.stream_integrity config engine actions final run

theorem deadlock_free (config : Config) : (pair config).DeadlockFree :=
  Tls.Proofs.deadlock_free config

theorem progress_enabled (config : Config) (state : Pair.State) (engine : config.Engine)
    (kernel : config.Kernel) (reachable : (pair config).Reachable state)
    (leftAlive : state.left.alive = true) (rightAlive : state.right.alive = true)
    : ∀ side,
        InTransit state side
        → state.saturated side = false
        → ∃ actor next,
            (pair config).step state (.pass actor) = some next ∧ work next < work state :=
  fun side transit admitting =>
    Tls.Proofs.progress_enabled
      config
      engine
      kernel
      state
      reachable
      side
      leftAlive
      rightAlive
      transit
      admitting

theorem pass_consumes_work (config : Config) (state next : Pair.State) (actor : Pair.Side)
    (engine : config.Engine) (kernel : config.Kernel)
    (reachable : (pair config).Reachable state)
    (stepped : (pair config).step state (.pass actor) = some next)
    : work next < work state :=
  (pass_settled
    config
    engine
    kernel
    state
    next
    actor
    (pair_coherent config engine state reachable)
    (pair_settled config engine kernel state reachable)
    stepped).2

theorem passes_bounded (config : Config) (start final : Pair.State)
    (actions : List Pair.Action) (engine : config.Engine) (kernel : config.Kernel)
    (reachable : (pair config).Reachable start)
    (run : CCF.Execution.Run (pair config) start actions final)
    : (actions.filter isPass).length + work final
      ≤ work start + (actions.map addedWork).sum :=
  run_work config engine kernel actions start final reachable run

theorem quiescent_delivered (config : Config) (start final : Pair.State)
    (actions : List Pair.Action) (engine : config.Engine) (kernel : config.Kernel)
    (initial : (pair config).init start)
    (run : CCF.Execution.Run (pair config) start actions final)
    (leftAlive : final.left.alive = true) (rightAlive : final.right.alive = true)
    : ∀ side,
        final.saturated side = false
        → (∀ actor, (pair config).step final (.pass actor) = none)
        → deliveredAlong config side start actions
          = acceptedAlong config side.peer start actions := by
  cases initial
  intro side admitting stuck
  exact
    Tls.Proofs.quiescent_delivered
      config
      engine
      kernel
      actions
      final
      run
      side
      leftAlive
      rightAlive
      admitting
      stuck

end Tls.Proofs.Claims
