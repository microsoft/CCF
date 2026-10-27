module

public import CCFRaft.Model
public import CCFRaft.Properties.Liveness.Assumptions
public import CCFRaft.Properties.Liveness.Assumptions.StableState
public import CCFRaft.Properties.Liveness.Model.Policy
public import CCF.Execution

import CCFRaft.Proofs.CommittedLogs
import CCFRaft.Proofs.Direct.CommitFrontier
import CCFRaft.Proofs.Election
import CCFRaft.Proofs.Liveness.MinimalCommit
import CCFRaft.Proofs.Liveness.MinimalWitness
import CCFRaft.Proofs.Witnesses

@[expose] public section

/-!
Safety and liveness theorems about the CCF-Raft model, each paired with a witness
lemma exhibiting a nontrivial execution relevant to that property.
-/

namespace CCFRaft.Properties

abbrev GlobalTrace := CCF.Execution.Trace Model.State Model.Action

open Model.Node

/-- Any two committed logs in a valid trace are prefix-comparable: those of
any two nodes, in any two states of the trace. -/
theorem committed_logs_prefix
    : forall (config : Finset NodeID),
      forall (nodes : List NodeID) (trace : GlobalTrace),
      forall (stateA stateB : Model.State),
      forall (left right : NodeID) (leftState rightState : NodeState),
        (trace.Valid (Model.transitionSystem config nodes)
          /\ stateA ∈ trace
          /\ stateB ∈ trace
          /\ (left, leftState) ∈ stateA.nodes
          /\ (right, rightState) ∈ stateB.nodes)
        -> leftState.committedLog <+: rightState.committedLog
            \/ rightState.committedLog <+: leftState.committedLog := by
  exact Proofs.CommittedLogs.committed_logs_prefix

/-- Witness: a valid trace has two states in which two distinct nodes have
nonempty committed logs. -/
lemma committed_logs_prefix_witness
    : exists (config : Finset NodeID),
    exists (nodes : List NodeID) (trace : GlobalTrace),
    exists (stateA stateB : Model.State),
    exists (left right : NodeID) (leftState rightState : NodeState),
      trace.Valid (Model.transitionSystem config nodes)
      /\ stateA ∈ trace
      /\ stateB ∈ trace
      /\ (left, leftState) ∈ stateA.nodes
      /\ (right, rightState) ∈ stateB.nodes
      /\ left ≠ right
      /\ leftState.committedLog ≠ []
      /\ rightState.committedLog ≠ [] := by
  exact Proofs.Witnesses.committed_logs_prefix_witness

/-- A successful network step from a state with unique node IDs preserves each
node's committed prefix. -/
theorem single_node_committed_log_monotonic
    : forall (config : Finset NodeID) (nodes : List NodeID),
      forall (pre post : Model.State),
      forall (nodeId : NodeID) (nodePre nodePost : NodeState),
      forall (action : Model.Action),
        ((pre.nodes.map Prod.fst).Nodup
          /\ (Model.transitionSystem config nodes).step pre action = some post
          /\ (nodeId, nodePre) ∈ pre.nodes
          /\ (nodeId, nodePost) ∈ post.nodes)
        -> nodePre.committedLog <+: nodePost.committedLog := by
  exact Proofs.Direct.single_node_committed_log_monotonic

/-- Witness: a successful step from a state with unique node IDs strictly extends
one node's nonempty committed log. -/
lemma single_node_committed_log_monotonic_witness
    : exists (config : Finset NodeID) (nodes : List NodeID),
    exists (pre post : Model.State),
    exists (nodeId : NodeID) (nodePre nodePost : NodeState),
    exists (action : Model.Action),
      (pre.nodes.map Prod.fst).Nodup
      /\ (Model.transitionSystem config nodes).step pre action = some post
      /\ (nodeId, nodePre) ∈ pre.nodes
      /\ (nodeId, nodePost) ∈ post.nodes
      /\ nodePre.committedLog ≠ []
      /\ nodePre.committedLog.length < nodePost.committedLog.length := by
  exact Proofs.Witnesses.single_node_committed_log_monotonic_witness

/-- No two distinct nodes are primary in the same term. -/
theorem election_safety
    : forall (config : Finset NodeID),
      forall (nodes : List NodeID) (trace : GlobalTrace) (state : Model.State),
      forall (left right : NodeID) (leftState rightState : NodeState),
        (trace.Valid (Model.transitionSystem config nodes)
          /\ state ∈ trace
          /\ (left, leftState) ∈ state.nodes
          /\ (right, rightState) ∈ state.nodes
          /\ leftState.role = .primary
          /\ rightState.role = .primary
          /\ leftState.currentTerm = rightState.currentTerm)
        -> left = right := by
  exact Proofs.Election.election_safety

/-- Witness: a valid trace has a state in which two nodes are primaries. -/
lemma election_safety_witness
    : exists (config : Finset NodeID),
    exists
    (nodes : List NodeID) (trace : GlobalTrace) (state : Model.State),
    exists (left right : NodeID) (leftState rightState : NodeState),
      trace.Valid (Model.transitionSystem config nodes)
      /\ state ∈ trace
      /\ (left, leftState) ∈ state.nodes
      /\ (right, rightState) ∈ state.nodes
      /\ leftState.role = .primary
      /\ rightState.role = .primary
      /\ left ≠ right := by
  exact Proofs.Witnesses.election_safety_witness

/-- Every positive commit index points to a signature entry. -/
theorem committed_frontier_is_signature
    : forall (config : Finset NodeID),
      forall (nodes : List NodeID) (trace : GlobalTrace) (state : Model.State),
      forall (node : NodeID) (nodeState : NodeState),
        (trace.Valid (Model.transitionSystem config nodes)
          /\ state ∈ trace
          /\ (node, nodeState) ∈ state.nodes
          /\ 0 < nodeState.commitIndex)
        -> isSignatureAt nodeState.log nodeState.commitIndex = true := by
  exact Proofs.Direct.committed_frontier_is_signature

/-- Witness: a valid trace has a state with a positive commit index. -/
lemma committed_frontier_is_signature_witness
    : exists (config : Finset NodeID),
    exists
    (nodes : List NodeID) (trace : GlobalTrace) (state : Model.State),
    exists (node : NodeID) (nodeState : NodeState),
      trace.Valid (Model.transitionSystem config nodes)
      /\ state ∈ trace
      /\ (node, nodeState) ∈ state.nodes
      /\ 0 < nodeState.commitIndex := by
  exact Proofs.Witnesses.committed_frontier_is_signature_witness

/-- Commitment within a bounded time from a live primary whose request is
already replicated to every node at `start`.
The timing constraints and the commit time are left for the proof to choose.
The constraints may depend only on the timing bounds and the maximum delay, and every large enough election timeout must meet them.
The commit time may depend only on the timing bounds and the maximum delay.
`Liveness.StableState` fixes the snapshot at `start`: every node in `nodes` is live
and has the primary's term and log, and every other node is a follower that knows
the primary. Every configuration, initial or appended, names only nodes in `nodes`. No crashes or packet drops occur from `start` onward.
Election scheduling constrains deadlines and requires eventual firing, with no
jitter bound, and no follower's deadline at `start` is within half an election
timeout. `TimeDiverges` already excludes finite traces.
Quorum-check step-downs follow CCF's acknowledgement-age check, and the primary
heard from every follower within a heartbeat interval before `start`.
No primary nominates a successor from `start` onward, and no earlier nomination
for the primary's term is still in flight.
The primary has finished reconfiguring at `start`, neither it nor any member of
its configuration was ever removed, and no configuration change is appended from
`start` onward.
This does not assume future stable leadership.
The proof takes the timing constraints `11 * maxDelay + 7 * max heartbeat 0 < E / 2`
and commits within `Proofs.Timed.commitDuration` with no backlog. -/
theorem commit_liveness
    : exists (timeoutConstraints : Liveness.Bounds -> Real -> Prop) (committedWithin
                                                                      : Liveness.Bounds
                                                                        -> Real
                                                                        -> Real),
        -- Not vacuous: whatever the other bounds and the delay, every large enough
        -- election timeout meets the constraints.
        (forall (bounds : Liveness.Bounds) (maxDelay : Real),
          exists low,
            forall electionTimeout,
              low <= electionTimeout
              -> timeoutConstraints { bounds with electionTimeout := electionTimeout }
                  maxDelay)
        /\ forall (config : Finset NodeID) (nodes : List NodeID),
            forall (bounds : Liveness.Bounds) (maxDelay : Real),
            forall (W : Type) [Liveness.HasProtocol W Model.State] [Liveness.HasTime W]
                    [Liveness.HasLive W] [Liveness.HasNetwork W] [Liveness.HasTimers W],
            forall (trace : CCF.Execution.Trace W Liveness.Event) (start : Nat),
            forall (leader : NodeID) (request : ReqID),
              -- Protocol actions follow Raft from its configured initial state.
              (Liveness.Satisfies trace (Liveness.protocolModel config nodes)
                -- Every configuration names only listed nodes: the initial one, and every
                -- one appended anywhere in the trace.
                /\ config ⊆ nodes.toFinset
                /\ (forall index step node entries entry members,
                      trace.stepAt index = some step
                      -> step.action = .local node (.append entries)
                      -> entry ∈ entries
                      -> entry.metadata.configuration = some members
                      -> members ⊆ nodes.toFinset)
                -- Time never decreases; only idle steps may advance it.
                /\ Liveness.Satisfies trace Liveness.timingModel
                -- Time grows without bound, excluding finite traces and infinite time stalls.
                /\ Liveness.TimeDiverges trace
                -- Actors may crash and not recover
                /\ Liveness.Satisfies trace Liveness.crashModel
                -- Track actual sends and consume each packet at most once, FIFO with loss.
                /\ Liveness.Satisfies trace (Liveness.deliveryModel config nodes)
                -- Nonnegative delay; no pending packet to a live target becomes overdue.
                /\ Liveness.Satisfies trace (Liveness.boundedDelayModel maxDelay)
                -- Each due peer send happens within the heartbeat bound, or ceases to be due.
                /\ Liveness.HeartbeatScheduling trace (some bounds.heartbeatInterval)
                -- Each due signature is appended within the signature bound, or ceases to be due.
                /\ Liveness.SignatureScheduling trace (some bounds.signatureInterval)
                -- A primary steps down on a quorum check only once some active configuration
                -- lacks a majority of itself and peers heard from within the election timeout.
                /\ Liveness.CheckQuorumScheduling trace bounds.electionTimeout
                -- Reset deadlines lie in [E/2, E] and change only on resets; no early firing.
                -- Overdue eligible nodes eventually time out
                -- or cease to be due. `none` adds no upper bound on scheduling delay.
                /\ Liveness.ElectionScheduling trace (some (bounds.electionTimeout / 2))
                    none
                -- The election timeout is long enough for the other bounds and the delay.
                /\ timeoutConstraints bounds maxDelay
                -- Fix the starting snapshot; this does not assert future stability.
                /\ Liveness.StableState trace start bounds nodes leader request
                -- No crashes from `start` onward; this does not forbid voluntary step-downs.
                /\ (forall index step node,
                      start <= index
                      -> trace.stepAt index = some step
                      -> Not (step.action = .crash node))
                -- No pending packet may be discarded from `start` onward.
                /\ (forall index step packet,
                      start <= index
                      -> trace.stepAt index = some step
                      -> Not (step.action = .drop packet))
                -- No primary nominates a successor from `start` onward.
                /\ (forall index step node,
                      start <= index
                      -> trace.stepAt index = some step
                      -> Not (step.action = .local node .nominateSuccessor))
                -- No configuration change is appended from `start` onward.
                /\ (forall index step node entries entry,
                      start <= index
                      -> trace.stepAt index = some step
                      -> step.action = .local node (.append entries)
                      -> entry ∈ entries
                      -> entry.metadata.configuration = none))
              -> exists index,
                  Liveness.Within trace start (committedWithin bounds maxDelay) index
                  /\ exists point state,
                      trace.stateAt index = some point
                      /\ CCF.MultiNodeTransitionSystem.nodeState
                            (Liveness.HasProtocol.proto point) leader
                          = some state
                      /\ Liveness.HasRequest state.committedLog request := by
  exact Proofs.Liveness.commit_liveness

/-- Witness: for any timing bounds with a nonnegative signature interval, and any
nonnegative delay, a one-node service whose node is primary throughout meets every
premise of `commit_liveness` from index one, except the timing constraints,
which every large enough election timeout meets. The node has no followers, so the
per-follower premises hold trivially. -/
lemma commit_liveness_witness
    : forall (bounds : Liveness.Bounds) (maxDelay : Real),
        0 <= bounds.signatureInterval
        -> 0 <= maxDelay
        -> exists (config : Finset NodeID) (nodes : List NodeID),
        exists
        (trace : CCF.Execution.Trace Liveness.DuelWorld Liveness.Event) (start : Nat),
        exists (leader : NodeID) (request : ReqID),
          -- Protocol actions follow Raft from its configured initial state.
          (Liveness.Satisfies trace (Liveness.protocolModel config nodes)
            -- Every configuration names only listed nodes: the initial one, and every
            -- one appended anywhere in the trace.
            /\ config ⊆ nodes.toFinset
            /\ (forall index step node entries entry members,
                  trace.stepAt index = some step
                  -> step.action = .local node (.append entries)
                  -> entry ∈ entries
                  -> entry.metadata.configuration = some members
                  -> members ⊆ nodes.toFinset)
            -- Time never decreases; only idle steps may advance it.
            /\ Liveness.Satisfies trace Liveness.timingModel
            -- Time grows without bound, excluding finite traces and infinite time stalls.
            /\ Liveness.TimeDiverges trace
            -- Actors may crash and not recover
            /\ Liveness.Satisfies trace Liveness.crashModel
            -- Track actual sends and consume each packet at most once, FIFO with loss.
            /\ Liveness.Satisfies trace (Liveness.deliveryModel config nodes)
            -- Nonnegative delay; no pending packet to a live target becomes overdue.
            /\ Liveness.Satisfies trace (Liveness.boundedDelayModel maxDelay)
            -- Each due peer send happens within the heartbeat bound, or ceases to be due.
            /\ Liveness.HeartbeatScheduling trace (some bounds.heartbeatInterval)
            -- Each due signature is appended within the signature bound, or ceases to be due.
            /\ Liveness.SignatureScheduling trace (some bounds.signatureInterval)
            -- A primary steps down on a quorum check only once some active configuration
            -- lacks a majority of itself and peers heard from within the election timeout.
            /\ Liveness.CheckQuorumScheduling trace bounds.electionTimeout
            -- Reset deadlines lie in [E/2, E] and change only on resets; no early firing.
            -- Overdue eligible nodes eventually time out
            -- or cease to be due. `none` adds no upper bound on scheduling delay.
            /\ Liveness.ElectionScheduling trace (some (bounds.electionTimeout / 2)) none
            -- Fix the starting snapshot; this does not assert future stability.
            /\ Liveness.StableState trace start bounds nodes leader request
            -- No crashes from `start` onward; this does not forbid voluntary step-downs.
            /\ (forall index step node,
                  start <= index
                  -> trace.stepAt index = some step
                  -> Not (step.action = .crash node))
            -- No pending packet may be discarded from `start` onward.
            /\ (forall index step packet,
                  start <= index
                  -> trace.stepAt index = some step
                  -> Not (step.action = .drop packet))
            -- No primary nominates a successor from `start` onward.
            /\ (forall index step node,
                  start <= index
                  -> trace.stepAt index = some step
                  -> Not (step.action = .local node .nominateSuccessor))
            -- No configuration change is appended from `start` onward.
            /\ (forall index step node entries entry,
                  start <= index
                  -> trace.stepAt index = some step
                  -> step.action = .local node (.append entries)
                  -> entry ∈ entries
                  -> entry.metadata.configuration = none)) := by
  exact Proofs.Liveness.MinimalWitness.commit_liveness_witness

end CCFRaft.Properties
