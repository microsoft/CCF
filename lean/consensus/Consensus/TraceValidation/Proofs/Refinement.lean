module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.TraceValidation.Proofs.Validator
public import Consensus.TraceValidation.Proofs.Section
public import Consensus.TraceValidation.Proofs.Handlers
public import CCF.Proofs.SectionsObservation

@[expose] public section

/-!
# An accepted trace refines the clean model (proof, not reviewed)

If the validator accepts the per-node streams, then there is one trace of
`Consensus.Model.transitionSystem env.genesis keys` (the frozen specification, with its
nonempty-genesis and committed-prefix-join conditions), and a nondecreasing map from
observations into it, such that at every lock-taking event (`opens`) the observed node's
clean state is `related` (reviewed, `Consensus.TraceValidation.Abs`) to the declared state the event
was compared with. The proof instantiates `CCF.Sections.observation_refines` with M_tv's
`Refinement` (`Consensus.TraceValidation.Proofs.refinement`), which reduces every section to
the obligation of the `cft.h` handler it runs, each proved in
`Consensus.TraceValidation.Proofs.Handlers`.
-/

namespace Consensus.TraceValidation.Proofs

open CCF.Sections
open CCF.MultiNodeTransitionSystem (nodeState)
open Consensus.Model.Node
open Consensus.TraceValidation.Exec (Ev)

/-- Every action of the guarded clean network is a step of the specification. -/
theorem guarded_embeds {g : CCF.Finset NodeID} {clean clean' : Consensus.Model.State}
    {action : Consensus.Model.Action}
    (h : guardedNext (Consensus.Model.protocol g) admit clean action = some clean')
    : Consensus.Model.networkStep g clean action = some clean' := by
  cases action with
  | deliver envelope => exact h
  | «local» node input =>
      have h' : (if admit (without clean.nodes node) node input = true then
          CCF.MultiNodeTransitionSystem.next (Consensus.Model.protocol g) clean (.local node input)
        else none) = some clean' := h
      by_cases admitted : admit (without clean.nodes node) node input = true
      · simp only [admitted, ite_true] at h'
        cases input with
        | initAsBackup entries =>
            have prefix_ : Consensus.Model.committedPrefixOf clean entries = true := by
              simp only [admit, List.any_eq_true] at admitted
              obtain ⟨⟨other, c⟩, member, holds⟩ := admitted
              simp only [Consensus.Model.committedPrefixOf, List.any_eq_true]
              exact ⟨(other, c), (List.mem_filter.mp member).1, holds⟩
            simp only [Consensus.Model.networkStep, prefix_, ite_true]
            exact h'
        | _ => exact h'
      · simp [admitted] at h'

/--
If the validator accepts the per-node streams, its observations are exactly the
streams' events, in order per node; each is consistent (by the reviewed `Exec.observe`)
with the declared state and the model's label at its trace point; and they refine the
clean specification at every lock-taking event.
-/
theorem validate_refines {env : Env}
    {streams : List (NodeID × List Ev)} {v : Verdict} (h : validate env streams = .ok v)
    : streamsMatch streams v.observations = true
      /\ (forall o, o ∈ v.observations -> Exec.consistent o.event o.declared = true)
      /\ CCF.ObservationRefinement.Refines
          (Consensus.Model.transitionSystem env.genesis v.keys) nodeState
          (fun node clean declared =>
            related env.names node clean declared.1 = true)
          opens v.observations := by
  obtain ⟨accepts, _, matches_, nonempty, consistent⟩ := validate_sound h
  exact ⟨matches_, consistent, observation_refines (refinement env (obligations env)) declare
    (fun node clean declared => related env.names node clean declared.1 = true)
    (fun node c l h idle => factors env node c l h idle) (frame env) v.keys _ _ (fun _ init keys => ⟨nonempty, keys, init⟩)
    (fun _ _ _ step => guarded_embeds step) v.observations accepts⟩

end Consensus.TraceValidation.Proofs
