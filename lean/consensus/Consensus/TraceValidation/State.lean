module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Lean.Data.Json

@[expose] public section

/-!
# Declared state: the cft.h variables M_tv tracks (reviewed)

One `Declared` state per node. Every field mirrors one implementation member, named
in its doc comment; there is no control, thread, lock or ghost state here. M_tv runs on
an extension of it (in `MTv/`, not reviewed). `Consensus.TraceValidation.Observe` compares
trace events against projections of this structure only. A reviewer checks each field
against the `cft.h` member its doc comment names.

The ledger is what the node holds: a node that joined from a snapshot holds only the
entries after the snapshot (`Ledger::init_idx`); the snapshot's index and view are
`base` and `baseView`. Every index-valued field is an absolute ledger index.
-/

namespace Consensus.TraceValidation.Exec

open Lean

abbrev NodeId := String

/-- `ccf::kv::Configuration::Nodes`: node to address, ordered by node id. -/
abbrev Nodes := List (NodeId × String)

/-- `ccf::kv::LeadershipState`. -/
inductive Leadership where
  | none
  | follower
  | preVoteCandidate
  | candidate
  | leader
deriving DecidableEq, Repr, Inhabited

/-- `ccf::kv::RetirementPhase`. -/
inductive Phase where
  | ordered
  | signed
  | completed
  | retiredCommitted
deriving DecidableEq, Repr, Inhabited

/-- `ccf::kv::Configuration`: `idx`, `nodes`, `rid`. -/
structure Config where
  idx : Nat
  nodes : Nodes
  rid : Nat
deriving DecidableEq, Repr, Inhabited

/-- `Aft::NodeState` minus `node_info` (address, in `Config`) and `last_ack_timeout` (timer). -/
structure Peer where
  /-- `NodeState::sent_idx`. -/
  sentIdx : Nat
  /-- `NodeState::match_idx`. -/
  matchIdx : Nat
deriving DecidableEq, Repr, Inhabited

/-- A ledger entry, as far as consensus can see it through `Store` and hooks. -/
structure Entry where
  /-- The view the entry was written in (`get_term_internal` of its index). -/
  term : Nat
  /-- `globally_committable`: a signature transaction. -/
  sig : Bool
  /-- The `nodes` of the `ConfigurationChangeHook` the entry triggers, if any. -/
  config : Option Nodes := none
  /-- Node ids of the retired_committed hook the entry triggers, if any. -/
  retired : List NodeId := []
deriving DecidableEq, Repr, Inhabited

structure Declared where
  /-- `aft::State::node_id`. -/
  nodeId : NodeId
  /-- `aft::State::current_view`. -/
  currentView : Nat := 0
  /-- `aft::State::last_idx`. -/
  lastIdx : Nat := 0
  /-- `aft::State::commit_idx`. -/
  commitIdx : Nat := 0
  /-- `aft::State::view_history.views`: start index of each view, view `v` at `views[v-1]`. -/
  views : Array Nat := #[]
  /-- `aft::State::committable_indices`. -/
  committable : List Nat := []
  /-- `aft::State::leadership_state`. -/
  leadership : Leadership := .none
  /-- `aft::State::membership_state == Retired`. -/
  retired : Bool := false
  /-- `aft::State::retirement_phase`. -/
  retirementPhase : Option Phase := none
  /-- `aft::State::retirement_idx`. -/
  retirementIdx : Option Nat := none
  /-- `aft::State::retirement_committable_idx`. -/
  retirementCommittableIdx : Option Nat := none
  /-- `aft::State::retired_committed_idx`. -/
  retiredCommittedIdx : Option Nat := none
  /-- `Aft::voted_for`. -/
  votedFor : Option NodeId := none
  /-- `Aft::leader_id`. -/
  leaderId : Option NodeId := none
  /-- `Aft::votes_for_me`: configuration index to (`Votes::votes`, `Votes::quorum`), by index. -/
  votesForMe : List (Nat × List NodeId × Nat) := []
  /-- `Aft::is_new_follower`. -/
  isNewFollower : Bool := false
  /-- `Aft::ticking`. -/
  ticking : Bool := false
  /-- `Aft::configurations`. -/
  configurations : List Config := []
  /-- `Aft::all_other_nodes`, ordered by node id. -/
  allOtherNodes : List (NodeId × Peer) := []
  /--
  The `init_as_backup` snapshot index (the host's `Ledger::init_idx`); 0 for a node that
  did not join from a snapshot.
  -/
  base : Nat := 0
  /-- The `init_as_backup` snapshot view; 0 when `base` is. -/
  baseView : Nat := 0
  /--
  `Aft::ledger` (`LedgerProxy`) contents the node holds, after `base`: entry `i` is
  `ledger[i - base - 1]`.
  -/
  ledger : Array Entry := #[]
  /--
  Not cft.h: the driver `Store`'s pending `retired_committed` entries
  (`logging_stub.h`), which `compact` turns into `set_retired_committed` calls,
  emulating the global-commit hook of a real node.
  -/
  rcEntries : List (Nat × List NodeId) := []
deriving DecidableEq, Inhabited

/-! ## Encodings shared by the model and the observation (as `cft_trace_msgpack.h`) -/

def Leadership.name : Leadership -> String
  | .none => "None"
  | .follower => "Follower"
  | .preVoteCandidate => "PreVoteCandidate"
  | .candidate => "Candidate"
  | .leader => "Leader"

def Phase.name : Phase -> String
  | .ordered => "Ordered"
  | .signed => "Signed"
  | .completed => "Completed"
  | .retiredCommitted => "RetiredCommitted"

def nodesJson (n : Nodes) : Json :=
  Json.mkObj (n.map fun (id, addr) => (id, Json.mkObj [("address", toJson addr)]))

def configsJson (cs : List Config) : Json :=
  toJson
    (cs.map
      fun c =>
        Json.mkObj
          [("idx", toJson c.idx), ("nodes", nodesJson c.nodes), ("rid", toJson c.rid)])

end Consensus.TraceValidation.Exec
