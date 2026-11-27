module

public import DisasterRecovery.Model
public import CCF.Execution

@[expose] public section

namespace DisasterRecovery.Properties

/-- Recovery configurations satisfying the model's validity predicate. -/
abbrev ValidConfig := { config : Model.Config // config.Valid }

/-- A finite or infinite network execution used to state global recovery properties. -/
abbrev Behaviour (config : Model.Config) :=
  CCF.Execution.Behaviour (Model.transitionSystem config)

open Model.Local in
/-- A recorded local step of one DR node: its before and after states, input, and outputs. -/
abbrev LocalStep :=
  CCF.MultiNodeTransitionSystem.LocalStep Location NodeState Operation Message
    Notification

open Model.Local in
/-- Consensus's vote freshness check on last signed TxIDs, not a log-prefix relation. -/
abbrev LogUpToDate (candidate voter : TxID) : Prop :=
  CCF.TxID.le voter candidate

open Model.Local in
/-- The candidate passes Consensus's log freshness check against a strict majority.
Valid model configs give one recovered ledger per configured node. -/
def UpToDateWithQuorum (config : Model.Config) (candidate : TxID) : Prop :=
  voteQuorum config.protocol
  <= (config.recovered.filter
        fun (_, voter) => decide (LogUpToDate candidate voter)).length

open Model.Local in
/-- The behaviour contains a state in which the node has accepted gossip from itself. -/
def ReceivedOwnGossip {config : Model.Config} (behaviour : Behaviour config)
    (node : Location)
    : Prop :=
  exists globalState,
    globalState ∈ behaviour
    /\ exists nodeState txid,
        (node, nodeState) ∈ globalState.nodes /\ (node, txid) ∈ nodeState.gossips

open Model.Local in
/-- `attempt` is pending at `index` in `state`, it is what running the transaction of its
event on some snapshot leaves pending, and nothing it read has been written since. -/
def Commits (config : Model.Config) (state : NodeState) (index : Nat) (attempt : Attempt)
    : Prop :=
  state.pending[index]? = some attempt
  /\ (exists snapshot : Store,
        (transaction config.protocol attempt.event).exec snapshot
        = { normal := attempt.normal, outputs := attempt.outputs, result := .ok () })
  /\ CCF.OCC.validates state.store attempt.normal.deps = true

namespace Behaviour

open Model.Local

/-- The node that executes a global action. -/
def actor : Model.Action -> Location
  | .local node _ => node
  | .deliver envelope => envelope.target

/-- The local operation executed by a global action. -/
def operation : Model.Action -> Operation
  | .local _ .retry => .retry
  | .local _ .timeout => .run .timeout
  | .local _ (.commit index) => .commit index
  | .deliver envelope => .run (Model.receive envelope.source envelope.payload)

/-- Step `step` of the behaviour, from state `step` to state `step + 1`, is taken by
`node`, and that node's local execution in the step emits `notification`. -/
def NotificationAt (config : Model.Config) (behaviour : Behaviour config) (step : Nat)
    (node : Location) (notification : Notification)
    : Prop :=
  exists before after action nodeBefore nodeAfter outputs,
    behaviour.stateAt step = some before
    /\ behaviour.stateAt (step + 1) = some after
    /\ behaviour.actionAt step = some action
    /\ actor action = node
    /\ CCF.MultiNodeTransitionSystem.nodeState before node = some nodeBefore
    /\ CCF.MultiNodeTransitionSystem.nodeState after node = some nodeAfter
    /\ ((Model.protocol config).step (CCF.Capabilities.record node) node nodeBefore
          (operation action)).run
          {}
        = some (nodeAfter, outputs)
    /\ notification ∈ outputs.notifications

end Behaviour

end DisasterRecovery.Properties
