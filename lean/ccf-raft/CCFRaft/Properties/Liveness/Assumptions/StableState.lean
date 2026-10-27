module

public import CCFRaft.Properties.Liveness.Model
public import CCFRaft.Properties.Liveness.Assumptions.Submitted
public import CCFRaft.Properties.Liveness.Assumptions.Window

@[expose] public section

open CCF.Execution (Trace)

namespace CCFRaft.Liveness

open Model.Node
open HasProtocol (proto)
open HasTime (time)
open HasLive (live)
open HasNetwork (pending)
open HasTimers (deadline)

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]
  [HasTimers W]

/-- At index `start`, `leader` is a settled primary holding `request`, and every
node in `nodes` is live and caught up with it. This fixes one snapshot of the
trace; it does not assert that the snapshot persists. -/
def StableState (trace : Trace W Event) (start : Nat) (bounds : Bounds)
    (nodes : List NodeID) (leader : NodeID) (request : ReqID)
    : Prop :=
  exists first leaderState,
    -- `start` names a recorded state, not a position past the trace.
    trace.stateAt start = some first
    -- The proposed primary exists in that state.
    /\ CCF.MultiNodeTransitionSystem.nodeState (proto first) leader = some leaderState
    -- It has not crashed before the starting point.
    /\ leader ∈ live first
    -- It is already primary, rather than awaiting an election.
    /\ leaderState.role = .primary
    -- The request is already in its log, but need not be committed.
    /\ HasRequest leaderState.log request
    -- Its reconfiguration is finished: one active configuration, and
    -- every completed removal has a committed retirement confirmation.
    /\ ReconfigurationSettled leaderState
    -- Neither it nor any member of its configuration was ever removed by
    -- a configuration in its log. A confirmed retirement outlasts a later
    -- re-addition, so such a node retires again once its commit index
    -- passes the old confirmation, forgets the primary, and grants
    -- pre-votes.
    /\ (forall node,
          (node = leader \/ node ∈ leaderState.activeMembers)
          -> retirementIndexInLog node leaderState.log = none)
    -- No earlier nomination for the primary's term is still in flight.
    /\ (forall packet,
          packet ∈ pending first
          -> Not
              (packet.envelope.payload
                = .proposeRequestVoteRequest leaderState.currentTerm))
    -- Every listed node exists and is fully caught up at this same instant.
    /\ forall node,
        node ∈ nodes
        -> exists state,
            CCF.MultiNodeTransitionSystem.nodeState (proto first) node = some state
            -- No listed node is already crashed.
            /\ node ∈ live first
            -- All have adopted the primary's term; none has a newer one.
            /\ state.currentTerm = leaderState.currentTerm
            -- Logs match exactly, including the request; no initial backlog.
            /\ state.log = leaderState.log
            -- Every other node is a follower that knows the primary, so
            -- none is campaigning or can grant a pre-vote.
            /\ (node = leader \/ (state.role = .follower /\ state.primaryKnown = true))
            -- No follower's election deadline is within half an election
            -- timeout of `start`.
            /\ (node = leader
                \/ time first + bounds.electionTimeout / 2 <= deadline first node)
            -- The primary heard from it within a heartbeat interval.
            /\ (node = leader
                \/ AckedAfter trace start leader node
                    (time first - bounds.heartbeatInterval))

end CCFRaft.Liveness
