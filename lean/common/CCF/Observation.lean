module

public import CCF.Execution

@[expose] public section

namespace CCF.ObservationRefinement

/-!
Observation-point refinement: the reviewed statement relating a traced
implementation to a specification.

An implementation is observed through a list of `Observation`s, one per traced event,
each carrying the node's declared state as snapshotted at that event. `Refines` says
that one specification execution, read at nondecreasing positions, explains every
observed point: the observed node's state in the specification at the corresponding
position is related by `rel` to the observed declared state. Only declared states,
`rel`, the event predicate and the specification appear here; how the implementation
model is built, and how it is proved to satisfy this, is not part of the statement.
-/

/-- One traced event: the node, the event, and the node's declared state at the event. -/
structure Observation (Node Event Declared : Type) where
  /-- The node that traced the event. -/
  node : Node
  /-- The traced event, with every label it carries. -/
  event : Event
  /-- The node's declared state, as snapshotted when the event was traced. -/
  declared : Declared

/--
`Refines spec nodeOf rel observed observations`: there is a specification trace and a
nondecreasing map `index` from observation positions to trace positions such that, at
every observation whose event satisfies `observed`, the trace's state at `index`
position has the observed node in a state related by `rel` (for that node) to the
observed declared state.
-/
def Refines {Node Event Declared SpecLocal : Type} (spec : TransitionSystem)
    (nodeOf : spec.State -> Node -> Option SpecLocal)
    (rel : Node -> SpecLocal -> Declared -> Prop)
    (observed : Event -> Bool) (observations : List (Observation Node Event Declared))
    : Prop :=
  exists (trace : Execution.Trace spec) (index : Nat -> Nat),
    (forall i j, i <= j -> index i <= index j)
    /\ forall (i : Nat) (observation : Observation Node Event Declared),
        observations[i]? = some observation
        -> observed observation.event = true
        -> exists state local_,
            trace.stateAt (index i) = some state
            /\ nodeOf state observation.node = some local_
            /\ rel observation.node local_ observation.declared

end CCF.ObservationRefinement
