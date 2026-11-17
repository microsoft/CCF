module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.TraceValidation.Event
public import Consensus.TraceValidation.State
public import Consensus.TraceValidation.Action

@[expose] public section

/-!
# Trace validation surface (reviewed)

Each trace event maps to exactly one M_tv action (`actionOf`). After the model
steps that action, the event is observed against the declared state (`Declared`) at the
trace point and the model's label (`observe`). Every field of every event is in
exactly one of these classes, or both of the last two, and every event carries exactly
the fields its trace point declares (`traceFields`):

* `state`, and the per-point fields in `stateFields`: projections of `Declared`;
* `inputFields`: consumed by the action (message identity, untraced choices,
  entry contents that only the hooks reveal);
* the label: values the model computed at the trace point (packets, indices).

Depends only on the declared state, the action type and event decoding.
-/

namespace Consensus.TraceValidation.Exec

open Lean

/--
The fields of each trace point besides `function`, as `cft_trace_msgpack.h` declares them.
An event must carry exactly these.
-/
def traceFields (e : Ev) : List String :=
  match e.function with
  | "send_append_entries" => ["state", "packet", "to_node_id", "match_idx", "sent_idx"]
  | "recv_append_entries_response" =>
      ["state", "packet", "from_node_id", "match_idx", "sent_idx"]
  | "recv_append_entries" =>
      ["state", "packet", "from_node_id", "leader_id", "is_new_follower"]
  | "execute_append_entries_sync" => ["state", "from_node_id", "ticking"]
  | "send_append_entries_response"
  | "send_request_vote"
  | "send_request_vote_response" => ["state", "packet", "to_node_id"]
  -- Only a regular vote request reads `voted_for` and `leader_id`.
  | "recv_request_vote" =>
      match e.msg.getObjValD "packet" |>.getObjValD "msg" |>.getStr? with
      | .ok "request_vote" =>
          ["state", "packet", "from_node_id", "voted_for", "leader_id"]
      | _ => ["state", "packet", "from_node_id"]
  | "recv_request_vote_response" => ["state", "packet", "from_node_id", "votes_for_me"]
  | "recv_propose_request_vote" => ["state", "packet", "from_node_id", "ticking"]
  | "tick" => ["state", "ticking"]
  | "become_pre_vote_candidate"
  | "become_leader" => ["state", "configurations", "votes_for_me", "leader_id"]
  | "become_candidate" =>
      ["state", "configurations", "voted_for", "votes_for_me", "leader_id"]
  | "become_follower" =>
      [
        "state",
        "configurations",
        "voted_for",
        "votes_for_me",
        "leader_id",
        "is_new_follower"
      ]
  | "nomination" | "batch_flush" | "replicate" => ["state"]
  | "step_down_and_nominate_successor" =>
      ["state", "configurations", "to_node_id", "leader_id"]
  | "replicate_entry" => ["state", "view", "seqno", "globally_committable", "ticking"]
  | "retired_committed_tx" => ["node_id", "seqno", "retired_node_id"]
  | "init_as_backup" => ["state", "seqno", "view"]
  | "add_configuration" => ["state", "configurations", "idx", "nodes", "rid"]
  | "commit" => ["state", "idx", "configurations", "leader_id"]
  | "drop_pending_to" => ["state", "from_node_id", "to_node_id", "packet"]
  | _ => []

/-- Fields an action consumes as input, by trace point. -/
def inputFields : String -> List String
  -- A receive's `from_node_id` and `packet` are labels: the delivered message's.
  -- The dropped message is not delivered: it is named by the event.
  | "drop_pending_to" => ["to_node_id", "packet"]
  -- `packet.idx` is the untraced batch size's choice; `to_node_id` tells a retired
  -- node's skipped send apart. Both are also labelled, so compared.
  | "send_append_entries" => ["to_node_id", "packet"]
  | "replicate_entry" => ["globally_committable"]
  -- On the primary the entry content is only visible through its hooks.
  | "retired_committed_tx" => ["retired_node_id"]
  -- `idx` is input only for the out-of-lock hook, whose snapshot version is untraced.
  | "add_configuration" => ["idx", "nodes"]
  | "init_as_backup" => ["seqno", "view"]
  | _ => []

def actionOf (e : Ev) : Except String Action := do
  let inputs ←
    (inputFields e.function).mapM
      fun k => do
        return (k, ← (e.msg.getObjVal? k).mapError fun _ => s!"input {k} missing")
  return { point := e.function, inputs }

/--
An `add_configuration` while the node is uninitialised (no role, view 0) is the
snapshot-install hook, which runs outside the lock: a section of its own.
-/
def outOfLock (s : Declared) (e : Ev) : Bool :=
  e.function == "add_configuration" && s.leadership == .none && s.currentView == 0

def optNat (k : String) (v : Option Nat) : List (String × Json) :=
  match v with
  | some n => [(k, toJson n)]
  | none => []

/-- `write_msgpack(aft::State)`: the snapshot every trace point but one carries. -/
def snapshot (s : Declared) : List (String × Json) :=
  let ci :=
    match s.committable with
    | [] => []
    | [a] => [a]
    | a :: rest => [a, rest.getLast?.getD a]
  [
    ("node_id", toJson s.nodeId),
    ("current_view", toJson s.currentView),
    ("last_idx", toJson s.lastIdx),
    ("commit_idx", toJson s.commitIdx),
    ("leadership_state", toJson s.leadership.name),
    ("membership_state", toJson (if s.retired then "Retired" else "Active"))
  ]
  ++ (match s.retirementPhase with
      | some p => [("retirement_phase", toJson p.name)]
      | none => [])
  ++ optNat "retirement_idx" s.retirementIdx
  ++ optNat "retirement_committable_idx" s.retirementCommittableIdx
  ++ optNat "retired_committed_idx" s.retiredCommittedIdx
  ++ [("committable_indices", toJson ci)]

def optId (v : Option NodeId) : Json :=
  match v with
  | some id => toJson id
  | none => Json.null

/-- `write_msgpack(std::map<Index, Votes>)`: by configuration index, votes sorted. -/
def votesJson (vs : List (Nat × List NodeId × Nat)) : Json :=
  toJson
    (vs.map
      fun (idx, votes, quorum) =>
        Json.mkObj
          [
            ("idx", toJson idx),
            ("quorum", toJson quorum),
            ("votes", toJson (votes.mergeSort (· <= ·)))
          ])

/-- The `aft::Aft` protocol variables, which some trace points carry, as projections. -/
def carried (s : Declared) : List (String × Json) :=
  [
    ("voted_for", optId s.votedFor),
    ("votes_for_me", votesJson s.votesForMe),
    ("leader_id", optId s.leaderId),
    ("is_new_follower", toJson s.isNewFollower),
    ("ticking", toJson s.ticking)
  ]

/-- Non-snapshot fields that are projections of `Declared` at the trace point. -/
def stateFields (e : Ev) (s : Declared) : List (String × Json) :=
  let peerId :=
    if e.function == "recv_append_entries_response" then
      getStr e.msg "from_node_id"
    else
      getStr e.msg "to_node_id"
  let peer :=
    match peerId with
    | .ok id => s.allOtherNodes.lookup id
    | .error _ => none
  [("configurations", configsJson s.configurations)]
  ++ carried s
  ++ (match peer with
      | some p => [("match_idx", toJson p.matchIdx), ("sent_idx", toJson p.sentIdx)]
      | none => [])
  ++ (match e.function with
      | "retired_committed_tx" => [("node_id", toJson s.nodeId)]
      | "replicate_entry" =>
          [("view", toJson s.currentView), ("seqno", toJson (s.lastIdx + 1))]
      | _ => [])

def compareObj (pfx : String) (model : List (String × Json)) (observed : Json)
    : Except String Unit := do
  let obs ← observed.getObj?
  for (k, m) in model do
    match obs.get? k with
    | some o =>
        unless o == m do
          throw s!"{pfx}{k}: observed {o.compress}, model {m.compress}"
    | none => throw s!"{pfx}{k}: absent, model {m.compress}"
  for (k, o) in obs.toList do
    unless model.any (·.1 == k) do
      throw s!"{pfx}{k}: observed {o.compress}, model has no such field"

/-- Observe event `e` against the state `s` at its trace point and the model's label. -/
def observe (e : Ev) (s : Declared) (label : Label) : Except String Unit := do
  let obj ← e.msg.getObj?
  let proj := stateFields e s
  for k in traceFields e do
    unless obj.contains k do
      throw s!"{k}: absent, a field of every {e.function} event"
  for (k, o) in obj.toList do
    if k == "function" then continue
    unless (traceFields e).contains k do
      throw s!"{k}: observed {o.compress}, not a field of {e.function} events"
    if k == "state" then compareObj "state." (snapshot s) o; continue
    match proj.lookup k <|> label.lookup k with
    | some m =>
        unless o == m do
          throw s!"{k}: observed {o.compress}, model {m.compress}"
    | none =>
        unless (inputFields e.function).contains k do
          throw s!"{k}: observed {o.compress}, neither observed nor consumed by the model"
  for (k, m) in label do
    unless obj.contains k do
      throw s!"{k}: absent, model {m.compress}"

/-- Whether event `e` is consistent with the declared state and label at its trace point. -/
def consistent (e : Ev) (declared : Declared × Label) : Bool :=
  match observe e declared.1 declared.2 with
  | .ok () => true
  | .error _ => false

/-! ## Lock-taking trace points -/

/-- Trace points that receive a message; they take the lock. -/
def recvHeads : List String :=
  [
    "recv_append_entries",
    "recv_append_entries_response",
    "recv_request_vote",
    "recv_request_vote_response",
    "recv_propose_request_vote"
  ]

/-- Trace points that take the lock and open a section (`cft.h` takes it before them). -/
def heads : List String :=
  recvHeads ++ ["tick", "replicate", "nomination", "init_as_backup", "drop_pending_to"]

end Consensus.TraceValidation.Exec
