module

public import CCFRaft.Properties.Liveness.Model.Timing

@[expose] public section

open CCF.Execution (Trace)

namespace CCFRaft.Liveness

open Model.Node

open HasProtocol (proto)
open HasLive (live)

variable {W : Type} [HasProtocol W Model.State] [HasLive W]

/-- At `index`, `leader` is live and the primary of `term`, and its retirement has
not committed. -/
abbrev Leads (trace : Trace W Event) (index : Nat) (leader : NodeID) (term : Nat)
    : Prop :=
  exists point state,
    trace.stateAt index = some point
    /\ Membership.mem (live point) leader
    /\ CCF.MultiNodeTransitionSystem.nodeState (proto point) leader = some state
    /\ state.role = .primary
    /\ state.currentTerm = term
    /\ Not (state.isRetiredCommitted leader)

/-- From index `start` on, `leader` leads `term`.
Other primaries, for example a partitioned primary of an older term, are allowed.
Needed: nodes can keep timing out and electing a new primary, each deposed before
its first signature is acknowledged. CCF makes this unlikely, not impossible, with
randomized election timeouts. `Properties.commit_liveness` does not assume it;
its proof derives a bounded stable window from a `StableState` snapshot. -/
def StableLeader (trace : Trace W Event) (start : Nat) (leader : NodeID) (term : Nat)
    : Prop :=
  (exists point, trace.stateAt start = some point)
  /\ forall index point,
      start <= index -> trace.stateAt index = some point -> Leads trace index leader term

end CCFRaft.Liveness
