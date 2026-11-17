module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.TraceValidation.Proofs.Refinement

@[expose] public section

/-!
# Trace validation (reviewed statement)

The validator `validate` (in `Consensus.TraceValidation.Validator`) checks a trace of
`cft.h` trace points, split into one stream per node. The theorem below is what
acceptance means: the accepted trace is a behaviour of the clean model
`Consensus.Model.transitionSystem` under a state refinement mapping. Properties are
stated and proved of the clean model only (`Consensus.Properties`); nothing here is
claimed of the implementation beyond this refinement.

To review, the state refinement mapping and the observations it is checked at:
`State` (the declared state: the `cft.h` variables of a node, with the ledger it
holds), `Abs` (the relation `related` of a clean node state to a declared state),
`Event` (decoded trace points), `Action` and `Observe` (what each trace point is
compared with), `CCF.Observation` (the refinement statement, in `lean/common`), and this
file. The behaviour refinement, that is the proof of the theorem, is in
`Consensus.TraceValidation.Proofs` and is not reviewed.
-/

namespace Consensus.TraceValidation

open CCF.MultiNodeTransitionSystem (nodeState)
open Consensus.Model.Node
open Consensus.TraceValidation.Exec (Ev)

/--
If the validator accepts the per-node streams, its observations are exactly the streams'
events, in order per node; each is consistent (`Exec.consistent`) with the declared state
and the model's label at its trace point; and they refine the clean specification
`Consensus.Model.transitionSystem` at every lock-taking event (`opens`): there is one
specification trace in which, at each such event, the node's clean state is `related` to
the declared state the event was compared with.
-/
theorem accepted_refines {env : Env}
    {streams : List (NodeID × List Ev)} {v : Verdict} (h : validate env streams = .ok v)
    : streamsMatch streams v.observations
      /\ (forall o, o ∈ v.observations -> Exec.consistent o.event o.declared = true)
      /\ CCF.ObservationRefinement.Refines
          (Consensus.Model.transitionSystem env.genesis v.keys) nodeState
          (fun node clean declared =>
            related env.names node clean declared.1 = true)
          opens v.observations :=
  Proofs.validate_refines h

end Consensus.TraceValidation
