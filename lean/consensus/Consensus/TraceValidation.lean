module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.TraceValidation.Proofs.Refinement

@[expose] public section

/-!
# Trace validation (reviewed statement)

`load` decodes a trace file of `cft.h` trace points into trace-wide parameters `env` and one
stream of events per node, and the validator `validate` checks them. The theorem below is
what acceptance means: the accepted trace is a behaviour of the clean model
`Consensus.Model.transitionSystem` under a state refinement mapping. Properties are
stated and proved of the clean model only (`Consensus.Properties`); nothing here is
claimed of the implementation beyond this refinement.

The reviewed surface is this file and the files directly in `TraceValidation/`: `State`
(the declared state: the `cft.h` variables of a node, with the ledger it holds), `Event`
(decoded trace points and per-node streams), `Input` (`load` and `env`), `Action` and
`Observe` (what each trace point is compared with), and `Abs` (the relation `related` of a
clean node state to a declared state); with `CCF.Observation` (the refinement statement, in
`lean/common`). They import only each other, the clean model and `lean/common`. This file's
only other references are the validator `validate` and the `observations` of its result
(`TraceValidation/Validator/`), and the proof `Proofs.validate_refines`; those, the model
of `cft.h` it runs (`TraceValidation/MTv/`) and the proofs (`TraceValidation/Proofs/`) are
not reviewed.
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
          (Consensus.Model.transitionSystem env.genesis (streams.map Prod.fst)) nodeState
          (fun node clean declared =>
            related env.names node clean declared.1 = true)
          opens v.observations :=
  Proofs.validate_refines h

end Consensus.TraceValidation
