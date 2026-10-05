import DisasterRecovery.Proofs.Lifting
import DisasterRecovery.Proofs.Trace

namespace DisasterRecovery.Proofs.History

open Shared
open Lifting

inductive Decoration (config : Model.Config)
    : Execution.Global.State -> List Model.State -> Execution.Global.State -> Prop where
  | nil (state) : Decoration config state [] state
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
  | @cons before middle after tail action step rest ih =>
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

structure Correspondence (config : Model.Config) (trace : Properties.GlobalTrace)
    (ghost : Execution.Global.State)
    : Prop where
  reachable : Execution.Global.Reachable config ghost
  suffix
    : forall state,
        state ∈ trace.states
        -> exists tail,
            Trace.Path (Model.transitionSystem config) state tail (erase ghost)

theorem history_correspondence {config : Model.Config} (trace : Properties.GlobalTrace)
    (valid : trace.Valid (Model.transitionSystem config))
    : exists initial tail final,
        trace.states = erase initial :: tail
        /\ (Execution.Global.transitionSystem config).init initial
        /\ Decoration config initial tail final
        /\ Correspondence config trace final := by
  obtain ⟨before, tail, after, states, initialized, path⟩ := Trace.valid_path valid
  obtain ⟨initial, init, linked⟩ := model_initial_lifts config before initialized
  obtain ⟨final, decorated, reachable, finalEq⟩ := trace_lifts path initial (.initial init) linked
  refine ⟨
    initial,
    tail,
    final,
    by simpa only [linked] using states,
    init,
    decorated,
    reachable,
    ?_
  ⟩
  intro state member
  rw [states] at member
  obtain ⟨suffix, rest⟩ := path.suffix member
  exact ⟨suffix, finalEq ▸ rest⟩

end DisasterRecovery.Proofs.History
