module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.Model
public import Consensus.TraceValidation.Observe
public import CCF.Observation

@[expose] public section

/-!
# State refinement mapping (reviewed)

The declared state is `Consensus.TraceValidation.Exec.Declared`: one structure of `cft.h`
members per node, each field documented with the member it mirrors. This file maps it to
the clean model's node state; `accepted_refines` says an accepted trace is a behaviour of
the clean model under this mapping.

`Declared.abs names d` is the clean `NodeState` that the declared state `d` stands for:
each clean field is a projection of declared fields. Node ids are strings in the
implementation and naturals in the clean model; `names` is the sorted table of the
trace's node ids, so the clean id is the rank and the clean order is the
implementation's `std::map` order.

A node that joined from a snapshot holds only the ledger after the snapshot index
`base`, so `abs`'s log is that suffix, while the clean log is the whole log. Indexes
are absolute in both.

`related names node c d` is the relation between the clean state `c` of `node` and its
declared state `d`: `d` is `node`'s, and, once `d` has a ledger entry, `c`'s log after
`base` is `abs`'s log, the snapshot's signature commits the node to the entries up to
`base` (`c`'s log has a signature at `base` in the snapshot view, and `c` has committed
it), and every other clean variable equals its `abs` value, except where the
implementation holds no value:

* send and match indexes are related only on a primary, for the nodes in
  `all_other_nodes` (the implementation has no entry for other nodes; the clean model
  keeps a total function that it never reads there);
* vote sets are related only in the role that collects them (cft.h resets
  `votes_for_me` when it starts collecting; the clean model keeps stale sets).

Before its first ledger entry, without a snapshot, a node is related to any clean state
that has committed nothing: the clean initial state of the genesis primary (`initialNodeState`) already is
primary at term 2 with the configuration entry, while the implementation starts with no
role, view 0 and an empty ledger and gets there through `force_become_primary` and the
genesis `replicate`.
-/

namespace Consensus.TraceValidation

open CCF (Finset)

open Consensus.Model.Node
open Consensus.TraceValidation.Exec (Declared Leadership NodeId Ev)

/-- The trace's node ids, sorted; a node's clean id is its position. -/
structure Names where
  known : Array NodeId

/-- The clean id of an implementation node id. Ids outside the table map past its end. -/
def Names.id (names : Names) (node : NodeId) : NodeID :=
  (names.known.findIdx? (· == node)).getD (names.known.size + node.length)

/-- The implementation node id of a clean id. -/
def Names.name (names : Names) (node : NodeID) : NodeId :=
  names.known[node]?.getD s!"#{node}"

def Names.set (names : Names) (nodes : List NodeId) : Finset NodeID :=
  Finset.ofList (nodes.map names.id)

/-- `ccf::kv::LeadershipState` to the clean role. -/
def absRole : Leadership -> Role
  | .none => .none
  | .follower => .follower
  | .preVoteCandidate => .preVoteCandidate
  | .candidate => .candidate
  | .leader => .primary

/--
A ledger entry: a signature, or a transaction with the metadata its hooks reveal. The
clean request id is not observable and is always 0.
-/
def absEntry (names : Names) (e : Exec.Entry) : Entry :=
  {
    term := e.term
    content :=
      if e.sig then
        .signature
      else
        .transaction 0
          {
            configuration := e.config.map fun ns => names.set (ns.map Prod.fst)
            retirementConfirmations := names.set e.retired
          }
  }

/--
The clean state a declared state stands for, a field-by-field projection. Its log is the
entries the node holds: indexes `d.base + 1` to `d.lastIdx`.
-/
def Exec.Declared.abs (names : Names) (d : Declared) : NodeState :=
  let peer (f : Exec.Peer -> Nat) (n : NodeID) : Nat :=
    match d.allOtherNodes.find? (fun (id, _) => names.id id == n) with
    | some (_, p) => f p
    | none => 0
  -- `votes_for_me` only counts the self-vote in configurations the node is in;
  -- a (pre-vote) candidate has always voted for itself.
  let votes := names.set (d.nodeId :: d.votesForMe.flatMap fun (_, vs, _) => vs)
  {
    role := absRole d.leadership
    currentTerm := d.currentView
    log := (d.ledger.toList.take (d.lastIdx - d.base)).map (absEntry names)
    commitIndex := d.commitIdx
    sentIndex := peer (·.sentIdx)
    matchIndex := peer (·.matchIdx)
    isNewFollower := d.isNewFollower
    votedFor := d.votedFor.map names.id
    primaryKnown := d.leaderId.isSome
    votesGranted := votes
    preVotesGranted := votes
    retiredCommittedIndex := d.retiredCommittedIdx
  }

/-- The nodes whose send and match indexes the declared state holds: a primary's peers. -/
def Exec.Declared.trackedPeers (names : Names) (d : Declared) : List NodeID :=
  if d.leadership == .leader then d.allOtherNodes.map fun (id, _) => names.id id else []

/--
The clean log has the snapshot's signature at the base, in the base view, and has
committed it; after the base it is the held entries; and every other clean variable
equals its `abs` value, except where the implementation holds none.
-/
def Exec.Declared.agrees (names : Names) (c : NodeState) (d : Declared) : Bool :=
  let a := d.abs names
  (d.base == 0
    || c.log[d.base - 1]? == some { term := d.baseView, content := .signature })
  && d.base <= d.commitIdx
  && c.role == a.role
  && c.currentTerm == a.currentTerm
  && c.log.drop d.base == a.log
  && c.commitIndex == a.commitIndex
  && (d.trackedPeers names).all
      (fun n => c.sentIndex n == a.sentIndex n && c.matchIndex n == a.matchIndex n)
  && c.isNewFollower == a.isNewFollower
  && c.votedFor == a.votedFor
  && c.primaryKnown == a.primaryKnown
  && (a.role != .candidate || c.votesGranted == a.votesGranted)
  && (a.role != .preVoteCandidate || c.preVotesGranted == a.preVotesGranted)
  && c.retiredCommittedIndex == a.retiredCommittedIndex

/-- The reviewed relation between a clean state and a declared state (see above). -/
def related (names : Names) (node : NodeID) (c : NodeState) (d : Declared) : Bool :=
  names.id d.nodeId == node
  && (d.agrees names c || (d.lastIdx == 0 && d.base == 0 && c.commitIndex == 0))

/-! ## Trace-wide parameters and observations -/

/-- Trace-wide parameters, computed by the decoder. -/
structure Env where
  /-- The trace's node ids, sorted. -/
  names : Names
  /-- Every node's address, as in configuration hooks. -/
  addrs : List (Exec.NodeId × String)
  /-- The genesis configuration: the node whose first event is `become_leader`. -/
  genesis : Finset NodeID

/-- Events that take the lock: the observation points. -/
def opens (e : Ev) : Bool := Exec.heads.contains e.function

/-- One observation: the node, its event, and its declared state and label at the event. -/
abbrev Obs := CCF.ObservationRefinement.Observation NodeID Ev (Declared × Exec.Label)

/--
The observations are exactly the streams' events: every observation is of a node that has a
stream, and every node's observed events are its stream's events, in order.
-/
def streamsMatch (streams : List (NodeID × List Ev)) (obs : List Obs) : Prop :=
  (forall o, o ∈ obs -> o.node ∈ streams.map Prod.fst)
  /\ forall k evs, (k, evs) ∈ streams -> (obs.filter (·.node == k)).map (·.event) = evs

end Consensus.TraceValidation
