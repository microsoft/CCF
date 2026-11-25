module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import CCF.Msgpack

public section

/-!
The records of a `ccf.cft` trace, as `src/consensus/aft/cft_trace_msgpack.h` writes them.
Each is declared with the reader of its MessagePack map: a field is named as its key.
-/

namespace Consensus.Replay

open CCF.Msgpack

msgpack_struct!
  /--
  `msg.state`: the consensus state of the node which emitted the event.
  A field which the state lacks is not observed.
  -/
  structure StateSnapshot where
    node_id : String := readStr
    current_view : Option Nat := readNat
    last_idx : Option Nat := readNat
    commit_idx : Option Nat := readNat
    leadership_state : Option String := readStr
    membership_state : Option String := readStr
    committable_indices : Option (List Nat) := readList readNat
    retirement_phase : Option String := readStr
    retirement_idx : Option Nat := readNat
    retirement_committable_idx : Option Nat := readNat
    retired_committed_idx : Option Nat := readNat

msgpack_struct!
  structure Packet.AppendEntries where
    term : Nat := readNat
    prev_idx : Nat := readNat
    prev_term : Nat := readNat
    idx : Nat := readNat
    leader_commit_idx : Nat := readNat
    term_of_idx : Nat := readNat
    contains_new_view : Bool := readBool

msgpack_struct!
  structure Packet.AppendEntriesResponse where
    term : Nat := readNat
    last_log_idx : Nat := readNat
    success : String := readStr

msgpack_struct!
  structure Packet.RequestVote where
    term : Nat := readNat
    last_committable_idx : Nat := readNat
    term_of_last_committable_idx : Nat := readNat

msgpack_struct!
  structure Packet.RequestVoteResponse where
    term : Nat := readNat
    vote_granted : Bool := readBool

msgpack_struct!
  structure Packet.ProposeRequestVote where
    term : Nat := readNat

deriving instance Inhabited for StateSnapshot

deriving instance
  DecidableEq, Repr
for
  Packet.AppendEntries, Packet.AppendEntriesResponse, Packet.RequestVote, Packet.RequestVoteResponse, Packet.ProposeRequestVote

/-- A consensus packet, by its `msg`. -/
inductive Packet where
  | appendEntries (packet : Packet.AppendEntries)
  | appendEntriesResponse (packet : Packet.AppendEntriesResponse)
  | requestVote (packet : Packet.RequestVote)
  | requestPreVote (packet : Packet.RequestVote)
  | requestVoteResponse (packet : Packet.RequestVoteResponse)
  | requestPreVoteResponse (packet : Packet.RequestVoteResponse)
  | proposeRequestVote (packet : Packet.ProposeRequestVote)
deriving DecidableEq, Repr

/-- The packet's `msg`. -/
def Packet.msg : Packet → String
  | .appendEntries _ => "append_entries"
  | .appendEntriesResponse _ => "append_entries_response"
  | .requestVote _ => "request_vote"
  | .requestPreVote _ => "request_pre_vote"
  | .requestVoteResponse _ => "request_vote_response"
  | .requestPreVoteResponse _ => "request_pre_vote_response"
  | .proposeRequestVote _ => "propose_request_vote"

/-- Read a packet: `msg` is its first key, and selects the reader of the others. -/
def Packet.read : Reader Packet := do
  let n ← readMapHeader
  unless ← strIs "msg" do
    throw "the first key of a packet must be msg"
  match ← readStr with
  | "append_entries" => .appendEntries <$> Packet.AppendEntries.readFields (n - 1)
  | "append_entries_response" =>
      .appendEntriesResponse <$> Packet.AppendEntriesResponse.readFields (n - 1)
  | "request_vote" => .requestVote <$> Packet.RequestVote.readFields (n - 1)
  | "request_pre_vote" => .requestPreVote <$> Packet.RequestVote.readFields (n - 1)
  | "request_vote_response" =>
      .requestVoteResponse <$> Packet.RequestVoteResponse.readFields (n - 1)
  | "request_pre_vote_response" =>
      .requestPreVoteResponse <$> Packet.RequestVoteResponse.readFields (n - 1)
  | "propose_request_vote" =>
      .proposeRequestVote <$> Packet.ProposeRequestVote.readFields (n - 1)
  | msg => throw s!"unknown packet '{msg}'"

msgpack_struct
  /-- An event which traces only the state of its node, such as `tick`. -/
  structure StateOnly where
    state : StateSnapshot := StateSnapshot.read

msgpack_struct
  /-- A `send_*` event. -/
  structure Send where
    state : StateSnapshot := StateSnapshot.read
    to_node_id : String := readStr
    packet : Packet := Packet.read

msgpack_struct
  /-- A `recv_*` event. -/
  structure Recv where
    state : StateSnapshot := StateSnapshot.read
    from_node_id : String := readStr
    packet : Packet := Packet.read

msgpack_struct
  structure ReplicateEntry where
    state : StateSnapshot := StateSnapshot.read
    seqno : Option Nat := readNat
    globally_committable : Bool := readBool

msgpack_struct
  structure AddConfiguration where
    state : StateSnapshot := StateSnapshot.read
    idx : Option Nat := readNat
    nodes : List String := readMapKeys

msgpack_struct
  /-- Traced by a ledger hook, with the node instead of its state. -/
  structure RetiredCommittedTx where
    node_id : String := readStr
    seqno : Nat := readNat
    retired_node_id : String := readStr

msgpack_struct
  structure InitAsBackup where
    state : StateSnapshot := StateSnapshot.read
    seqno : Nat := readNat
    view : Nat := readNat

deriving instance Inhabited for StateOnly

/-- The fields of an event, by its `function`. -/
inductive Body where
  | stateOnly (event : StateOnly)
  | send (event : Send)
  | recv (event : Recv)
  | replicateEntry (event : ReplicateEntry)
  | addConfiguration (event : AddConfiguration)
  | retiredCommittedTx (event : RetiredCommittedTx)
  | initAsBackup (event : InitAsBackup)
deriving Inhabited

/-- Read the `n` fields which follow the `function` of an event. -/
def Body.read (function : String) (n : Nat) : Reader Body :=
  if function.startsWith "send_" then
    .send <$> Send.readFields n
  else if function.startsWith "recv_" then
    .recv <$> Recv.readFields n
  else
    match function with
    | "replicate_entry" => .replicateEntry <$> ReplicateEntry.readFields n
    | "add_configuration" => .addConfiguration <$> AddConfiguration.readFields n
    | "retired_committed_tx" => .retiredCommittedTx <$> RetiredCommittedTx.readFields n
    | "init_as_backup" => .initAsBackup <$> InitAsBackup.readFields n
    | _ => .stateOnly <$> StateOnly.readFields n

/-- The state an event traces: only its node, for a `retired_committed_tx`. -/
def Body.state : Body → StateSnapshot
  | .stateOnly event => event.state
  | .send event => event.state
  | .recv event => event.state
  | .replicateEntry event => event.state
  | .addConfiguration event => event.state
  | .initAsBackup event => event.state
  | .retiredCommittedTx event =>
      { (default : StateSnapshot) with node_id := event.node_id }

/-- `msg`: an event, or a command of the scenario driver, which replay skips. -/
inductive Msg where
  | cmd
  | event (function : String) (body : Body)
deriving Inhabited

/-- Read a `msg`: `function` or `cmd` is its first key. -/
def Msg.read : Reader Msg := do
  let start ← get
  let n ← readMapHeader
  if ← strIs "function" then
    let function ← readStr
    return .event function (← Body.read function (n - 1))
  unless ← strIs "cmd" do
    throw "the first key of a msg must be function or cmd"
  set start
  skip
  return .cmd

msgpack_struct
  /-- What a process emits for an event: the record of a Fluentd message. -/
  structure Emitted where
    pid : String := readStr
    m_ts : Nat := readNat
    msg : Msg := Msg.read

deriving instance Inhabited for Emitted

/--
Read a Fluentd Forward message `[tag, time, record]`: the time in nanoseconds and the
record, if the tag is `ccf.cft`. A message of another tag is skipped, without decoding it.
-/
def readMessage : Reader (Option (Option Nat × Emitted)) := do
  unless (← readArrayHeader) == 3 do
    throw "expected [tag, time, record]"
  if ← strIs "ccf.cft" then
    return some (← readEventTime, ← Emitted.read)
  skip
  skip
  skip
  return none

end Consensus.Replay
