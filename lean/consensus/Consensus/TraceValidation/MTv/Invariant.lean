module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.TraceValidation.MTv.Aft

@[expose] public section

/-!
# M_tv invariants (not reviewed)

The refinement proof relates a node's clean state to its declared state by `Rel`
(`Consensus.TraceValidation.Proofs.Obligation`): the reviewed agreement (`agrees`) or,
before the node's first ledger entry, the clean initial state; in both cases with the
local invariant `inv` of the declared state. Messages in flight satisfy `msgInv`.

The machine (`Consensus.TraceValidation.MTv.Machine`) evaluates `inv` at every release and
rejects the trace when a conjunct fails, so each handler obligation assumes `inv` of the
declared state at release rather than proving it. A rejection by a conjunct is of one of
two kinds, stated in its doc comment:

* *first kind*: the state cannot arise in a correct implementation, so the trace exhibits
  an implementation (or driver) bug;
* *second kind*: legitimate implementation behaviour that the frozen specification cannot
  express; `knownDifference` describes it, and the diagnostic says it is a known
  implementation and specification difference.

`msgInv` stays a conclusion of each obligation about the messages it sends; the
diagnostic lock-step check (`Consensus.TraceValidation.Validator.Lockstep`) evaluates it at every
send.

Each conjunct of `inv` is named; the names are what rejections and lock-step findings
report.
-/

namespace Consensus.TraceValidation

open Consensus.Model.Node
open Consensus.TraceValidation.Exec (State Leadership)

/-- Signature indexes of the declared ledger in `(lo, hi]`. -/
def signaturesIn (d : State) (lo hi : Nat) : List Nat :=
  (List.range' (lo + 1) (hi - lo)).filter fun i => d.ledger[i - 1]?.any (·.sig)

/--
Declared configurations against the clean ones, as (index, sorted members): equal, except
that the first declared index may be later than the clean one, up to the commit index.
-/
def configurationsMatch (commitIdx : Nat)
    : List (Nat × List NodeID) -> List (Nat × List NodeID) -> Bool
  | (i, n) :: ds, (j, m) :: cs =>
      n == m && (i == j || (j <= i && i <= commitIdx)) && ds == cs
  | [], [] => true
  | _, _ => false

/-- The named conjuncts of the local invariant. -/
def invChecks (names : Names) (d : State) : List (String × Bool) :=
  let a := abs names d
  let self := names.id d.nodeId
  [
    -- First kind: `lastIdx` counts the ledger.
    ("ledger_size", d.ledger.size == d.lastIdx),
    -- First kind: the commit index is within the ledger.
    ("commit_le_last", decide (d.commitIdx <= d.lastIdx)),
    -- First kind: `committable_indices` are the signatures above the commit index.
    ("committable", d.committable == signaturesIn d d.commitIdx d.lastIdx),
    -- First kind: a positive commit index is at a signature.
    ("commit_at_signature", d.commitIdx == 0 || d.ledger[d.commitIdx - 1]?.any (·.sig)),
    -- First kind for nodes started by `create`/`join`: each entry's term is the view the
    -- view history assigns to its index. A leader elected with commit index 0 skips the
    -- election rollback (cft.h `become_leader`), which only driver start states reach.
    (
      "terms_are_views",
      (List.range' 1 d.lastIdx).all
        fun i => d.ledger[i - 1]?.map (·.term) == some (d.viewAt i)
    ),
    -- First kind: the view history has at most one start per view.
    ("views_bounded", decide (d.views.size <= d.currentView)),
    -- First kind: a candidate has started no view since it became one (it incremented its
    -- view from one bounding the view history and appended nothing), so its own view has
    -- no start yet.
    ("candidate_views", d.leadership != .candidate || d.views.size < d.currentView),
    -- First kind: a leader is its own leader.
    ("leader_knows_itself", d.leadership != .leader || d.leaderId == some d.nodeId),
    -- First kind: at view 0 a node has no ledger and is neither leader nor candidate.
    (
      "view_zero",
      d.currentView != 0
      || (d.lastIdx == 0 && d.leadership != .leader && d.leadership != .candidate)
    ),
    -- First kind (given that a primary rejects an unchanged configuration): the declared
    -- configurations are the clean active configurations, except that the first may sit at
    -- a later index at or below the commit index. A joiner's snapshot hook (hooks.h)
    -- installs the latest configuration at the version of the snapshot's last nodes-table
    -- write, which follows the configuration's entry when a later write (a node's
    -- deletion) kept the membership. cft.h reads a configuration's index only against
    -- later configurations and indexes above the commit index, or for its order, so the
    -- two indexes behave alike.
    (
      "configurations",
      d.lastIdx == 0
      || configurationsMatch d.commitIdx
          (d.configurations.map
            (fun c => (c.idx, (names.set (c.nodes.map Prod.fst)).sort)))
          ((activeConfigurations a.log a.commitIndex).map
            fun c => (c.index, c.nodes.sort))
    ),
    -- Second kind (`knownDifference`): a node with a role has exactly the clean eligible
    -- peers. cft.h keeps peers across a rollback that the clean model drops.
    (
      "peers",
      d.lastIdx == 0
      || d.leadership == .none
      || d.allOtherNodes.map (fun (id, _) => names.id id)
          == (eligiblePeers a (names.id d.nodeId)).sort
    ),
    -- First kind: the same for a node without a role.
    (
      "peers_without_role",
      d.lastIdx == 0
      || d.leadership != .none
      || d.allOtherNodes.map (fun (id, _) => names.id id)
          == (eligiblePeers a (names.id d.nodeId)).sort
    ),
    -- First kind: every view start is positive.
    ("views_positive", d.views.all (0 < ·)),
    -- First kind: the node voted for is named in the table.
    ("voted_for_named", d.votedFor.all fun x => names.name (names.id x) == x),
    -- First kind: once the node's own retirement is committed, the latch is set.
    (
      "latched",
      d.retiredCommittedIdx.isSome
      || !(d.ledger.toList.take d.commitIdx).any (·.retired.contains d.nodeId)
    ),
    -- First kind: the latched index is the first committed entry confirming this node's
    -- retirement (what the clean `recordCommit` latches).
    (
      "rci_first",
      d.retiredCommittedIdx
      == firstLogIndexAfter (a.log.take d.commitIdx) 0
          fun c => decide (self ∈ c.metadata.retirementConfirmations)
    ),
    -- First kind: the latched confirmation follows a configuration that removes this node,
    -- so the clean model clears the role when it latches.
    (
      "rci_retired",
      d.retiredCommittedIdx.all fun j => (retirementIndexInLog self (a.log.take j)).isSome
    ),
    -- First kind: a primary without ledger entries has no peers. The clean primary with
    -- an empty log has no eligible peers, so it cannot nominate one.
    (
      "empty_leader_alone",
      d.lastIdx != 0 || d.leadership != .leader || d.allOtherNodes.isEmpty
    ),
    -- Second kind (`knownDifference`): an initialised node without ledger entries has no
    -- peers, as the clean node without a log has no eligible peers. cft.h keeps peers
    -- across a rollback to an empty ledger.
    (
      "empty_ledger_alone",
      (d.currentView == 0 && d.leadership == .none)
      || d.lastIdx != 0
      || d.allOtherNodes.isEmpty
    ),
    -- First kind: configuration members and peers are named in the table, so `names.id`
    -- is injective on them and string membership is clean id membership.
    (
      "names_round_trip",
      (d.configurations.flatMap (·.nodes.map Prod.fst)
        ++ d.allOtherNodes.map Prod.fst).all
        fun id => names.name (names.id id) == id
    ),
    -- First kind: M_tv's `is_retired_committed` is the clean `isRetiredCommitted`.
    ("retired_committed", d.isRetiredCommitted == decide (a.isRetiredCommitted self)),
    -- First kind: the pending retired-committed records are exactly the uncommitted
    -- entries with retirement confirmations, in ledger order, with their confirmations.
    (
      "rc_entries",
      d.rcEntries
      == (List.range' (d.commitIdx + 1) (d.lastIdx - d.commitIdx)).filterMap
          fun i =>
            d.ledger[i - 1]?.bind
              fun e => if e.retired.isEmpty then none else some (i, e.retired)
    ),
    -- First kind: a leader has committed everything the clean model can commit, i.e. its
    -- commit index is at least the clean `highestCommittableIndex` (which never goes
    -- below the commit index, so the two are equal).
    (
      "commit_maximal",
      d.leadership != .leader || highestCommittableIndex a self <= d.commitIdx
    ),
    -- First kind: the view history is sorted by index.
    ("views_sorted", (d.views.toList.zip d.views.toList.tail).all fun (x, y) => x <= y),
    -- First kind: every view starts at most one past the end of the ledger.
    ("views_le_last", d.views.all (· <= d.lastIdx + 1)),
    -- First kind: every ledger entry has a positive term.
    ("positive_terms", d.ledger.all (0 < ·.term)),
    -- First kind: a leader has sent and seen acknowledged no index beyond its ledger.
    -- Stricter than cft.h: cft.h tolerates one peer acknowledging beyond the leader's log
    -- (it only throws once a quorum does); a correct follower never does.
    (
      "peer_bounds",
      d.leadership != .leader
      || d.allOtherNodes.all
          fun (_, p) => p.sentIdx <= d.lastIdx && p.matchIdx <= d.lastIdx
    ),
    -- First kind: ids in ledger configurations and retirement confirmations are named in
    -- the table.
    (
      "ledger_names_round_trip",
      d.ledger.all
        fun e =>
          ((e.config.getD []).map Prod.fst ++ e.retired).all
            fun id => names.name (names.id id) == id
    ),
    -- First kind: once the node knows a configuration or peer, the name table is strictly
    -- sorted, so it is duplicate-free and `names.id` is order-preserving on named ids.
    (
      "names_sorted",
      (d.configurations.isEmpty && d.allOtherNodes.isEmpty)
      || (names.known.toList.zip names.known.toList.tail).all fun (x, y) => decide (x < y)
    ),
    -- First kind: the members of each active configuration are distinct (cft.h's
    -- `Configuration::Nodes` is a map), so a configuration's size is its clean size.
    (
      "configuration_members_distinct",
      d.configurations.all
        fun c => (c.nodes.map Prod.fst).eraseDups == c.nodes.map Prod.fst
    ),
    -- First kind: a (pre-)candidate has one vote record per active configuration, at its
    -- index with its quorum, whose votes are duplicate-free and are exactly the members of
    -- that configuration that are the node itself or voted for it in any configuration.
    (
      "votes_for_me",
      !(d.leadership == .candidate || d.leadership == .preVoteCandidate)
      || (d.votesForMe.length == d.configurations.length
          &&  let voters := d.nodeId :: d.votesForMe.flatMap (·.2.1)
              (d.votesForMe.zip d.configurations).all
                fun ((i, vs, q), c) =>
                  let members := (c.nodes.map Prod.fst).filter voters.contains
                  i == c.idx
                  && q == State.quorum c.nodes.length
                  && vs.eraseDups == vs
                  && vs.all members.contains
                  && members.all vs.contains)
    ),
    -- First kind: the node's own id is named in the table (the validator's table holds
    -- every node id of the trace), so `names.id` separates it from other named ids.
    ("self_named", names.name (names.id d.nodeId) == d.nodeId),
    -- First kind: a primary without ledger entries knows no configuration. A joining node
    -- learns its start configuration before it has ledger entries, but becomes primary
    -- only by an election, which needs ledger entries, or as the genesis node, which has
    -- no configuration until its first entry's hook.
    (
      "empty_leader_unconfigured",
      d.lastIdx != 0 || d.leadership != .leader || d.configurations.isEmpty
    ),
    -- First kind: a leader is not retired-committed. cft.h clears the leadership when the
    -- node's retirement commits, and a retired-committed node does not become leader.
    ("leader_not_retired_committed", d.leadership != .leader || !d.isRetiredCommitted),
    -- First kind: the peers are strictly sorted by node id (cft.h's `all_other_nodes` is a
    -- `std::map`), so re-inserting a peer keeps every peer in place.
    (
      "peers_sorted",
      (d.allOtherNodes.zip d.allOtherNodes.tail).all fun (p, q) => decide (p.1 < q.1)
    ),
    -- First kind: a leader's pending retired-committed records name no other node that is a
    -- member of the configurations left once the record commits (CCF never reuses a node
    -- id, and a node's removal commits before its retirement is confirmed). cft.h would
    -- otherwise erase the peer at the commit and re-create it, with an AppendEntries, as it
    -- drops the older configurations.
    (
      "rc_entries_retired",
      d.leadership != .leader
      || d.rcEntries.all
          fun (ver, ids) =>
            ids.all
              fun id =>
                id == d.nodeId
                || !(Exec.commit.pop ver d.configurations).any (·.nodes.any (·.1 == id))
    ),
    -- First kind: a leader's pending retirement confirmations name removed nodes (a node is
    -- confirmed only once its removal commits, and CCF never reuses a node id), so no
    -- configuration it appends names them.
    (
      "rc_entries_removed",
      d.leadership != .leader
      || d.rcEntries.all
          fun (_, ids) => ids.all fun id => decide (names.id id ∈ removedNodes a.log)
    ),
    -- First kind: a leader's nodes whose retirement completed are removed nodes (CCF never
    -- reuses a node id), so no configuration it appends names them.
    (
      "retirement_completed_removed",
      d.leadership != .leader || decide (a.retirementCompletedNodes ⊆ removedNodes a.log)
    ),
    -- First kind: a leader that is the only node of its configurations has not been removed
    -- (its latest configuration names it).
    (
      "alone_not_removed",
      d.leadership != .leader
      || !d.configurations.all (·.nodes.all (·.1 == d.nodeId))
      || decide (self ∉ removedNodes a.log)
    ),
    -- First kind: every active configuration has a member. cft.h's configurations come from
    -- the start state or from the ledger, and a configuration entry names at least one node.
    ("configurations_nonempty", d.configurations.all fun c => !c.nodes.isEmpty),
    -- First kind: every member of an active configuration is in the name table (the
    -- validator's table holds every node id of the trace, and a configuration lists its
    -- members with their addresses), so `names.id` orders members as their names do.
    (
      "members_known",
      (d.configurations.flatMap (·.nodes.map Prod.fst)).all names.known.contains
    )
  ]

/-- The local invariant of a declared state. -/
def inv (names : Names) (d : State) : Bool := (invChecks names d).all (·.2)

/--
The conjuncts whose failure is legitimate implementation behaviour that the frozen
specification cannot express (second kind), with the scenario.
-/
def knownDifference : String -> Option String
  | "peers" =>
      some
        ("cft.h keeps a peer in all_other_nodes across a rollback that the clean model "
          ++ "drops: n0 appends a configuration adding n3 without replicating it and is "
          ++ "partitioned, n1 wins the next view, and when n0 rolls the configuration back it "
          ++ "keeps n3 as a peer")
  | "empty_ledger_alone" =>
      some
        ("cft.h keeps a peer in all_other_nodes across a rollback to an empty ledger, "
          ++ "which the clean model, without configurations, does not have: as for peers, "
          ++ "when the rolled-back configuration was the node's only one")
  | _ => none

/-- Why `inv` fails: the failed conjuncts, each second-kind one with its known difference. -/
def invDiagnostic (names : Names) (d : State) : String :=
  let failed := (invChecks names d).filter (!·.2) |>.map (·.1)
  let described :=
    failed.map
      fun n =>
        match knownDifference n with
        | some why =>
            s!"{n} (accepted by the implementation, rejected by validation: known implementation and specification difference: {why})"
        | none => n
  s!"invariant fails: {", ".intercalate described}"

/--
What every message in flight satisfies: it goes between two different nodes whose ids
round-trip through the name table, an AppendEntries batch is in one positive view, the
ids in its entries' configurations and retirement confirmations round-trip too, and its
transactions have request id 0.
-/
def msgInv (names : Names) (e : CCF.Envelope NodeID Message) : Bool :=
  names.id (names.name e.source) == e.source
  && e.source != e.target
  && (match e.payload with
      | .appendEntriesRequest r =>
          r.entries.all
            fun x =>
              ((x.content.metadata.configuration.map (·.sort)).getD []
                ++ x.content.metadata.retirementConfirmations.sort).all
                fun i => names.id (names.name i) == i
      | _ => true)
  && (match e.payload with
      | .appendEntriesRequest r =>
          (r.entries.all
            fun x =>
              some x.term == r.entries.getLast?.map (·.term)
              && 0 < x.term
              && x.term <= r.term)
          && (r.prevLogIndex == 0 || 0 < r.prevLogTerm)
      | _ => true)
  -- Every AppendEntries transaction has request id 0, as `absEntry` writes it: the clean
  -- request id is not observable, so received entries round-trip through the ledger.
  && (match e.payload with
      | .appendEntriesRequest r =>
          r.entries.all
            fun x =>
              match x.content with
              | .transaction q _ => q == 0
              | .signature => true
      | _ => true)

end Consensus.TraceValidation
