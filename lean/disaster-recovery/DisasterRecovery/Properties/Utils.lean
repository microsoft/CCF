module

public import DisasterRecovery.Model
public import CCF.Execution

@[expose] public section

namespace DisasterRecovery.Properties

/-- A finite or infinite network execution used to state global recovery properties. -/
abbrev GlobalTrace (config : Model.Config) :=
  CCF.Execution.Trace (Model.transitionSystem config)

open Model.Local in
/-- A recorded local step of one DR node: its before and after states, input, and outputs. -/
abbrev LocalStep :=
  CCF.MultiNodeTransitionSystem.LocalStep Location NodeState Event Message Notification

open Model.Local in
/-- Raft's vote freshness check on last signed TxIDs, not a log-prefix relation. -/
abbrev LogUpToDate (candidate voter : TxID) : Prop :=
  voter.view < candidate.view
  \/ (voter.view = candidate.view /\ voter.seqno <= candidate.seqno)

open Model.Local in
/-- The candidate passes Raft's log freshness check against a strict majority.
Valid model configs give one recovered ledger per configured node. -/
def UpToDateWithQuorum (config : Model.Config) (candidate : TxID) : Prop :=
  voteQuorum config.protocol
  <= (config.recovered.filter
        fun (_, voter) => decide (LogUpToDate candidate voter)).length

open Model.Local in
/-- The trace contains a state in which the node has accepted gossip from itself. -/
def ReceivedOwnGossip {config : Model.Config} (trace : GlobalTrace config)
    (node : Location)
    : Prop :=
  exists globalState,
    globalState ∈ trace
    /\ exists nodeState txid,
        (node, nodeState) ∈ globalState.nodes /\ (node, txid) ∈ nodeState.gossips

namespace Trace

open Model.Local

/-- The node that executes a global action. -/
def actor : Model.Action -> Location
  | .local node _ => node
  | .deliver envelope => envelope.target

/-- The local recovery event executed by a global action. -/
def event : Model.Action -> Event
  | .local _ .retry => .retry
  | .local _ .timeout => .timeout
  | .deliver envelope => Model.receive envelope.source envelope.payload

/-- Step `step` of the trace, from state `step` to state `step + 1`, is taken by
`node`, and that node's local execution in the step emits `notification`. -/
def NotificationAt (config : Model.Config) (trace : GlobalTrace config) (step : Nat)
    (node : Location) (notification : Notification)
    : Prop :=
  exists before after action nodeBefore nodeAfter outputs,
    trace.stateAt step = some before
    /\ trace.stateAt (step + 1) = some after
    /\ trace.actionAt step = some action
    /\ actor action = node
    /\ CCF.MultiNodeTransitionSystem.nodeState before node = some nodeBefore
    /\ CCF.MultiNodeTransitionSystem.nodeState after node = some nodeAfter
    /\ ((Model.protocol config).step (CCF.Capabilities.record node) node nodeBefore
          (event action)).run
          {}
        = some (nodeAfter, outputs)
    /\ notification ∈ outputs.notifications

end Trace

end DisasterRecovery.Properties
