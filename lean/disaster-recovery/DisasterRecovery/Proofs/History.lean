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
  induction path
    using @Trace.Path.rec (Model.transitionSystem config) generalizing ghost with
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
structure Correspondence (config : Model.Config) (trace : Properties.GlobalTrace config)
    (bound : Nat) (ghost : Execution.Global.State)
    : Prop where
  /-- The instrumented state is reachable under the same recovery configuration. -/
  reachable : Execution.Global.Reachable config ghost
  /-- Every trace state up to `bound` has a model path to the erased ghost state. -/
  suffix
    : forall i state,
        i <= bound
        -> trace.stateAt i = some state
        -> exists tail,
            Trace.Path (Model.transitionSystem config) state tail (erase ghost)

/-- The prefix of a valid trace up to any of its positions is decorated by a reachable
ghost execution. -/
theorem history_correspondence {config : Model.Config}
    (trace : Properties.GlobalTrace config) {bound : Nat}
    (inTrace : (trace.stateAt bound).isSome)
    : exists ghost, Correspondence config trace bound ghost := by
  obtain ⟨last, found⟩ := Option.isSome_iff_exists.mp inTrace
  obtain ⟨before, first, initialized⟩ := trace.valid_init
  obtain ⟨initial, init, linked⟩ := model_initial_lifts config before initialized
  obtain ⟨tail, path⟩ := Trace.valid_path 0 bound first (by simpa using found)
  obtain ⟨final, _, reachable, finalEq⟩ := trace_lifts path initial (.initial init) linked
  refine ⟨final, reachable, fun i state le atI => ?_⟩
  obtain ⟨suffix, rest⟩ :=
    Trace.valid_path i (bound - i) atI (by rwa [Nat.add_sub_cancel' le])
  exact ⟨suffix, finalEq ▸ rest⟩

end DisasterRecovery.Proofs.History
