import DisasterRecovery.Proofs.GlobalTemporal

/-!
# Human-reviewed system properties

Review these statements together with the definitions and assumptions in
`DisasterRecovery.Protocol`. Each theorem explicitly applies a machine-checked
lemma from `DisasterRecovery.Proofs`; changing a statement must preserve that
checked connection. Intermediate facts remain lemmas in the proof modules.
-/

namespace DisasterRecovery.Properties

section Local

open Protocol.Model Protocol.Temporal

/-! ## Local safety and progress -/

theorem gossip_freezes_after_choice
    (config : Config)
    (state : NodeState)
    (source : Location)
    (txid : TxID)
    (chosen : state.chosen.isSome = true) :
    let output := step config state (.receiveGossip source txid .accepted)
    output.state = state /\ output.accepted = false :=
  Proofs.Temporal.gossip_freezes_after_choice config state source txid chosen

theorem rejected_gossip_stutters
    (config : Config)
    (state : NodeState)
    (source : Location)
    (txid : TxID) :
    let output := step config state (.receiveGossip source txid .rejected)
    output.state = state /\ output.accepted = false :=
  Proofs.Temporal.rejected_gossip_stutters config state source txid

theorem quorum_advance_opens
    (config : Config)
    (state : NodeState)
    (phase : state.phase = .voting)
    (quorum : state.votes.length >= voteQuorum config) :
    let output := (advance config state false).get!
    output.state.phase = .opening /\
      output.state.openKind = some .quorum /\
      output.effects = [.opening .quorum] :=
  Proofs.Temporal.quorum_advance_opens config state phase quorum

theorem aligned_opening_timeout_completes
    (config : Config)
    (state : NodeState) :
    let opening := {
      state with
      phase := .opening
      timeoutState := .opening
    }
    let output := step config opening .timeout
    output.state.phase = .open /\
      output.state.timeoutState = .opening /\
      output.effects = [.completed] :=
  Proofs.Temporal.aligned_opening_timeout_completes config state

theorem fair_aligned_opening_progress
    {config : Config}
    (execution : Execution config)
    (initial : AlignedOpening (execution.states 0))
    (fair : WeakFairness execution AlignedOpening
      (fun _ event => event = .timeout)) :
    EventuallyFrom 0
      (fun n => (execution.states n).phase = .open) :=
  Proofs.Temporal.fair_aligned_opening_progress execution initial fair

end Local

section Global

open Protocol.Model hiding Config
open Protocol.Global Protocol.Invariants Protocol.Quorum Protocol.Committed Protocol.GlobalTemporal
open Protocol.Temporal (EventuallyFrom)

/-! ## Reachability and quorum safety -/

theorem reachable_well_formed
    {config : Config}
    {state : State}
    (reachable : Reachable config state) :
    WellFormed config state :=
  Proofs.Invariants.reachable_well_formed reachable

theorem reachable_quorum_invariant
    {config : Config}
    {state : State}
    (reachable : Reachable config state) :
    QuorumInvariant config state :=
  Proofs.Quorum.reachable_quorum_invariant reachable

theorem quorum_opener_unique
    {config : Config}
    {state : State}
    {first second : Location}
    (reachable : Reachable config state)
    (firstOpened : QuorumOpened state first)
    (secondOpened : QuorumOpened state second) :
    first = second :=
  Proofs.Quorum.quorum_opener_unique
    reachable firstOpened secondOpened

/-! ## Committed-prefix safety -/

theorem full_gossip_selection_preserves_commit
    {config : Config}
    {state : State}
    {opener : Location}
    {committed : TxID}
    (reachable : Reachable config state)
    (full : FullGossipSelection config state opener)
    (durable : DurableCommit config committed) :
    exists recovered,
      recoveredTxID config opener = some recovered /\
        TxID.PrefixOf committed recovered :=
  Proofs.Committed.full_gossip_selection_preserves_commit
    reachable full durable

theorem quorum_open_preserves_commit
    {config : Config}
    {state : State}
    {opener : Location}
    {committed : TxID}
    (reachable : Reachable config state)
    (opened : QuorumOpened state opener)
    (full : FullGossipSelection config state opener)
    (durable : DurableCommit config committed) :
    exists recovered,
      recoveredTxID config opener = some recovered /\
        TxID.PrefixOf committed recovered :=
  Proofs.Committed.quorum_open_preserves_commit
    reachable opened full durable

/-! ## Conditional global progress -/

theorem fair_opening_completes
    {config : Config}
    (execution : Execution config)
    (initial : Reachable config (execution.states 0))
    (fair : Fair execution)
    {start : Nat}
    {node : Location}
    (active : node ∈ (execution.states start).active)
    (phase : HasPhase (execution.states start) node .opening) :
    EventuallyFrom start (fun n =>
      CompletedOpen (execution.states n) node) :=
  Proofs.GlobalTemporal.fair_opening_completes
    execution initial fair active phase

theorem fair_some_opener_completes
    {config : Config}
    (execution : Execution config)
    (initial : Reachable config (execution.states 0))
    (fair : Fair execution)
    (activeNonempty : (execution.states 0).active ≠ []) :
    EventuallyFrom 0 (fun n =>
      exists node, CompletedOpen (execution.states n) node) :=
  Proofs.GlobalTemporal.fair_some_opener_completes
    execution initial fair activeNonempty

theorem global_progress
    {config : Config}
    (execution : Execution config)
    (initial : Reachable config (execution.states 0))
    (fair : Fair execution)
    (broadcast : BroadcastBeforeCompletion execution)
    (activeNonempty : (execution.states 0).active ≠ []) :
    EventuallyFrom 0 (fun n =>
      exists node, CompletedOpen (execution.states n) node) /\
    EventuallyFrom 0 (fun n =>
      forall node, node ∈ (execution.states 0).active ->
        Terminal (execution.states n) node) :=
  Proofs.GlobalTemporal.global_progress
    execution initial fair broadcast activeNonempty

theorem single_completion_path_joins_others
    {config : Config}
    (execution : Execution config)
    (initial : Reachable config (execution.states 0))
    (fair : Fair execution)
    (broadcast : BroadcastBeforeCompletion execution)
    {start : Nat}
    {opener : Location}
    (completed : CompletedOpen (execution.states start) opener)
    (onlyOpener : OnlyOpenerCompletesFrom execution start opener) :
    EventuallyFrom start (fun n =>
      forall node, node ∈ (execution.states start).active ->
        node = opener \/ node ∈ (execution.states n).restarts) :=
  Proofs.GlobalTemporal.single_completion_path_joins_others
    execution initial fair broadcast completed onlyOpener

theorem quorum_path_progress
    {config : Config}
    (execution : Execution config)
    (initial : Reachable config (execution.states 0))
    (fair : Fair execution)
    (broadcast : BroadcastBeforeCompletion execution)
    {start : Nat}
    {opener : Location}
    (opened : QuorumOpened (execution.states start) opener)
    (completed : CompletedOpen (execution.states start) opener)
    (quorumOnly : QuorumOnlyCompletions execution) :
    QuorumOpened (execution.states start) opener /\
      CompletedOpen (execution.states start) opener /\
      EventuallyFrom start (fun n =>
        forall node, node ∈ (execution.states start).active ->
          node = opener \/ node ∈ (execution.states n).restarts) :=
  Proofs.GlobalTemporal.quorum_path_progress
    execution initial fair broadcast opened completed quorumOnly

end Global

end DisasterRecovery.Properties
