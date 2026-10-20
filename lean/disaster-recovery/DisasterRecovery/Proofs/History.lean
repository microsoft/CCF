module

public import DisasterRecovery.Proofs.Lifting
public import DisasterRecovery.Proofs.Trace

@[expose] public section

namespace DisasterRecovery.Proofs.History

open CCF
open Lifting

/-- Decorated steps whose erased successor states form the given model-state list. -/
inductive Decoration (config : Model.Config)
    : Execution.Global.State -> List Model.State -> Execution.Global.State -> Prop where
  /-- An empty decoration leaves the instrumented state unchanged. -/
  | nil (state) : Decoration config state [] state
  /-- Prepend an instrumented step and its erased successor. -/
  | cons {before middle after tail} {action}
    (step : Execution.Global.next config before action = some middle)
    (rest : Decoration config middle tail after)
    : Decoration config before (erase middle :: tail) after

lemma trace_lifts {config : Model.Config} {before after : Model.State} {tail}
    (path : Trace.Path (Model.transitionSystem config) before tail after)
    (ghost : Execution.Global.State) (reachable : Execution.Global.Reachable config ghost)
    (linked : erase ghost = before)
    : exists final,
        Decoration config ghost tail final
        /\ Execution.Global.Reachable config final
        /\ erase final = after := by
  induction path generalizing ghost with
  | nil => exact ⟨ghost, .nil _, reachable, linked⟩
  | @cons before middle after tail action step _ ih =>
      obtain ⟨ghostAction, ghostMiddle, _, ghostStep, middleEq⟩ :=
        step_lifts config ghost action middle
          (Invariants.reachable_well_formed reachable).nodeKeysNodup
          (by simpa only [linked] using step)
      obtain ⟨final, decorated, reachableFinal, finalEq⟩ :=
        ih ghostMiddle (.step reachable ghostStep) middleEq
      exact ⟨
        final,
        middleEq ▸ Decoration.cons ghostStep decorated,
        reachableFinal,
        finalEq
      ⟩

/-- A reachable decorated state with a model execution suffix from every trace state
up to `bound`. -/
structure Correspondence (config : Model.Config) (trace : Properties.GlobalTrace)
    (bound : Nat) (ghost : Execution.Global.State)
    : Prop where
  /-- The instrumented state is reachable under the same recovery configuration. -/
  reachable : Execution.Global.Reachable config ghost
  /-- Every trace state up to `bound` has a model path to the erased ghost state. -/
  suffix
    : forall index,
        index <= bound
        -> exists tail,
            Trace.Path (Model.transitionSystem config) (trace.states index) tail
              (erase ghost)

/-- Every finite prefix of a valid trace is decorated by a reachable ghost execution. -/
theorem history_correspondence {config : Model.Config} (trace : Properties.GlobalTrace)
    (valid : trace.Valid (Model.transitionSystem config)) (bound : Nat)
    : exists ghost, Correspondence config trace bound ghost := by
  obtain ⟨initial, init, linked⟩ := model_initial_lifts config (trace.states 0) valid.1
  obtain ⟨final, _, reachable, finalEq⟩ :=
    trace_lifts (Trace.valid_path valid 0 bound) initial (.initial init) linked
  refine ⟨final, reachable, fun index le => ?_⟩
  have path := Trace.valid_path valid index (bound - index)
  rw [Nat.zero_add] at finalEq
  rw [Nat.add_sub_cancel' le, ← finalEq] at path
  exact ⟨_, path⟩

end DisasterRecovery.Proofs.History
