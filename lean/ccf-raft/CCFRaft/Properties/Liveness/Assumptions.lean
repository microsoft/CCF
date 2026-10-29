module

public import CCFRaft.Properties.Liveness.Model
public import CCFRaft.Properties.Liveness.Assumptions.StableLeader
public import CCFRaft.Properties.Liveness.Assumptions.Submitted
public import CCFRaft.Properties.Liveness.Assumptions.Window

@[expose] public section

/-!
Assumptions and goals of the liveness theorem about an execution: a stable
primary, a starting snapshot (`StableState`) and a committed request.
Short, single-declaration definitions are here.
Larger groups of related declarations are imported from `Properties/Liveness/Assumptions/`.
Unlike the scheduling constraints, these are not
environment constraints; each theorem states the ones it needs.
-/

open CCF.Execution (Trace)

namespace CCFRaft.Liveness

open Model.Node

open HasProtocol (proto)
open HasTime (time)
open HasLive (live)

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]

/-- The request is in the primary's committed prefix, not merely replicated or signed. -/
def RequestCommitted (trace : Trace W Event) (leader : NodeID) (request : ReqID)
    (index : Nat)
    : Prop :=
  exists point state,
    trace.stateAt index = some point
    /\ CCF.MultiNodeTransitionSystem.nodeState (proto point) leader = some state
    /\ HasRequest state.committedLog request

/-- The concrete predicate tested by the primary's signature-commit scan. -/
def SignatureReady (state : NodeState) (self : NodeID) (index : Nat) : Prop :=
  index <= state.log.length
  /\ isSignatureAt state.log index = true
  /\ termAt state.log index = state.currentTerm
  /\ hasQuorum (state.activeConfigurations.filter fun config => config.index <= index)
      (state.activeMembers.filter
        fun node => node = self \/ state.matchIndex node >= index)

end CCFRaft.Liveness
