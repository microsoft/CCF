import DisasterRecovery.Proofs.Committed
import DisasterRecovery.Proofs.Invariants
import DisasterRecovery.Proofs.Model
import DisasterRecovery.Proofs.Quorum

/-!
# Human-reviewed system properties

Review these statements together with the definitions and assumptions in
`DisasterRecovery.Protocol`. Each theorem explicitly applies a machine-checked
lemma from `DisasterRecovery.Proofs`; changing a statement must preserve that
checked connection. Intermediate facts remain lemmas in the proof modules.
-/

namespace DisasterRecovery.Properties

section Local

open Protocol.Model

/-! ## Local safety -/

theorem gossip_freezes_after_choice
    (config : Config)
    (state : NodeState)
    (source : Location)
    (txid : TxID)
    (chosen : state.chosen.isSome = true) :
    let output := step config state (.receiveGossip source txid .accepted)
    output.state = state /\ output.accepted = false :=
  Proofs.Model.gossip_freezes_after_choice config state source txid chosen

theorem rejected_gossip_stutters
    (config : Config)
    (state : NodeState)
    (source : Location)
    (txid : TxID) :
    let output := step config state (.receiveGossip source txid .rejected)
    output.state = state /\ output.accepted = false :=
  Proofs.Model.rejected_gossip_stutters config state source txid

theorem quorum_advance_opens
    (config : Config)
    (state : NodeState)
    (phase : state.phase = .voting)
    (quorum : state.votes.length >= voteQuorum config) :
    let output := (advance config state false).get!
    output.state.phase = .opening /\
      output.state.openKind = some .quorum /\
      output.effects = [.opening .quorum] :=
  Proofs.Model.quorum_advance_opens config state phase quorum

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
  Proofs.Model.aligned_opening_timeout_completes config state

end Local

section Global

open Protocol.Model hiding Config
open Protocol.Global Protocol.Invariants Protocol.Quorum Protocol.Committed

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
        TxID.EarlierThan committed recovered :=
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
        TxID.EarlierThan committed recovered :=
  Proofs.Committed.quorum_open_preserves_commit
    reachable opened full durable

end Global

end DisasterRecovery.Properties
