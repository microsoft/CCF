-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import Tls.Proofs.Local

@[expose] public section

/-!
Every connection of a node stays coherent whatever its peer and owner do, and a step of one
connection leaves the others alone.
-/

namespace Tls.Proofs

open Tls.Model

theorem endpoint_step_local (config : Config) (engine : config.Engine) (saturated : Bool)
    (endpoint next : Node.Endpoint) (event : Node.Event)
    (coherent : Coherent config endpoint.conn)
    (stepped : endpoint.step config saturated event = some next)
    : Coherent config next.conn := by
  cases event with
  | pass =>
      simp only [Node.Endpoint.step, Option.map_eq_some_iff] at stepped
      obtain ⟨io, passed, rfl⟩ := stepped
      exact (pass_local config _ _ io engine coherent (fun _ member => by simp at member) passed).1
  | send data =>
      simp only [Node.Endpoint.step, Option.map_eq_some_iff] at stepped
      obtain ⟨conn, sent, rfl⟩ := stepped
      exact send_local config data _ conn coherent sent
  | abort =>
      simp only [Node.Endpoint.step] at stepped
      split at stepped
      · cases stepped
        exact abort_local config _ coherent
      · cases stepped
  | peerSend record =>
      simp only [Node.Endpoint.step] at stepped
      split at stepped
      · cases stepped
      · cases stepped
        exact coherent
  | peerReceive =>
      simp only [Node.Endpoint.step] at stepped
      split at stepped
      · cases stepped
      · cases stepped
        exact coherent
  | peerClose =>
      simp only [Node.Endpoint.step] at stepped
      split at stepped
      · cases stepped
      · cases stepped
        exact coherent

theorem node_coherent (config : Config) (engine : config.Engine) (state : Node.State)
    (reachable : (node config).Reachable state)
    : ∀ endpoint ∈ state.endpoints, Coherent config endpoint.conn := by
  induction reachable using @CCF.TransitionSystem.Reachable.rec (node config) with
  | initial initialized =>
      cases initialized
      intro endpoint member
      simp at member
  | @step state next action _ transition ih =>
      cases action with
      | accept =>
          cases transition
          intro endpoint member
          rcases List.mem_append.mp member with old | new
          · exact ih endpoint old
          · have fresh : endpoint = {} := by simpa using new
            rw [fresh]
            exact initial_local config engine
      | admission saturated =>
          cases transition
          exact ih
      | connection index event =>
          simp only [Node.step, Option.bind_eq_bind, Option.bind_eq_some_iff, Option.pure_def,
            Option.some.injEq] at transition
          obtain ⟨endpoint, found, after, stepped, rfl⟩ := transition
          intro member isMember
          rcases List.mem_or_eq_of_mem_set isMember with old | new
          · exact ih member old
          · rw [new]
            exact
              endpoint_step_local
                config
                engine
                state.saturated
                endpoint
                after
                event
                (ih endpoint (List.mem_of_getElem? found))
                stepped

theorem connections_isolated (config : Config) (state next : Node.State) (index : Nat)
    (event : Node.Event)
    (stepped : Node.step config state (.connection index event) = some next)
    : next.saturated = state.saturated
      ∧ (∃ before after,
          state.endpoints[index]? = some before
          ∧ before.step config state.saturated event = some after
          ∧ next.endpoints[index]? = some after)
      ∧ ∀ other, other ≠ index → next.endpoints[other]? = state.endpoints[other]? := by
  simp only [Node.step, Option.bind_eq_bind, Option.bind_eq_some_iff, Option.pure_def,
    Option.some.injEq] at stepped
  obtain ⟨endpoint, found, after, changed, rfl⟩ := stepped
  refine ⟨rfl, ⟨endpoint, after, found, changed, ?_⟩, ?_⟩
  · have bound : index < state.endpoints.length := by
      rcases List.getElem?_eq_some_iff.mp found with ⟨bound, _⟩
      exact bound
    simp [bound]
  · intro other different
    simp [List.getElem?_set_ne (Ne.symm different)]

end Tls.Proofs
