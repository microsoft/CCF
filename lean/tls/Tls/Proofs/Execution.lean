-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import CCF.Execution

@[expose] public section

/-!
Executable runs of a transition system, used to build the concrete executions behind the
witness lemmas and the tests.
-/

namespace Tls.Proofs

/-- Apply a list of actions in order, if each is enabled. -/
def exec (system : CCF.TransitionSystem) (state : system.State)
    : List system.Action → Option system.State
  | [] => some state
  | action :: rest => (system.step state action).bind (exec system · rest)

theorem exec_run (system : CCF.TransitionSystem) (actions : List system.Action)
    (start final : system.State) (ran : exec system start actions = some final)
    : CCF.Execution.Run system start actions final := by
  induction actions generalizing start with
  | nil =>
      cases ran
      exact .nil _
  | cons action rest ih =>
      simp only [exec, Option.bind_eq_some_iff] at ran
      obtain ⟨middle, stepped, remaining⟩ := ran
      exact .cons stepped (ih middle remaining)

theorem exec_reachable (system : CCF.TransitionSystem) (actions : List system.Action)
    (start final : system.State) (reachable : system.Reachable start)
    (ran : exec system start actions = some final)
    : system.Reachable final := by
  induction actions generalizing start with
  | nil =>
      cases ran
      exact reachable
  | cons action rest ih =>
      simp only [exec, Option.bind_eq_some_iff] at ran
      obtain ⟨middle, stepped, remaining⟩ := ran
      exact ih middle (.step reachable stepped) remaining

/-- The state a list of enabled actions reaches; `start` if one of them is disabled. -/
def execD (system : CCF.TransitionSystem) (start : system.State)
    (actions : List system.Action)
    : system.State :=
  (exec system start actions).getD start

theorem execD_run (system : CCF.TransitionSystem) (actions : List system.Action)
    (start : system.State) (enabled : (exec system start actions).isSome = true)
    : CCF.Execution.Run system start actions (execD system start actions) := by
  obtain ⟨final, ran⟩ := Option.isSome_iff_exists.mp enabled
  simp only [execD, ran, Option.getD_some]
  exact exec_run system actions start final ran

theorem execD_reachable (system : CCF.TransitionSystem) (actions : List system.Action)
    (start : system.State) (reachable : system.Reachable start)
    (enabled : (exec system start actions).isSome = true)
    : system.Reachable (execD system start actions) := by
  obtain ⟨final, ran⟩ := Option.isSome_iff_exists.mp enabled
  simp only [execD, ran, Option.getD_some]
  exact exec_reachable system actions start final reachable ran

end Tls.Proofs
