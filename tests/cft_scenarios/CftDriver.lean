-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

/-!
Lean bindings for the consensus scenario driver.

Each command is implemented by the C function named in its `extern` attribute, in
`src/consensus/aft/test/driver.cpp`, which forwards it to `CftDriver` in `driver.h`.
A scenario is an `IO` action built from these commands and registered with `scenario`.

After each command that can alter state, the driver asserts that every node's commit index
is safe. After the last command, it confirms that the network can still make progress.
-/

namespace CftDriver

/-- Text passed to the driver. Numeric literals are accepted, so `2` is `"2"`. -/
structure Text where
  /-- The text passed to the driver. -/
  text : String

instance : Coe String Text := ⟨Text.mk⟩

instance {n : Nat} : OfNat Text n := ⟨⟨toString n⟩⟩

/-- A node identifier. -/
abbrev NodeId := Text

/-- The term of the primary which a command addresses, or `latest`. -/
abbrev Term := Text

/-- The primary in the highest term. Commands addressed to it do nothing if there is none. -/
def latest : Term := "latest"

/-! ## Membership -/

/-- Create the first node, as primary in term 2 of a network containing only itself. -/
@[extern "cft_start_node"]
opaque startNode (node : @& NodeId) : IO Unit

/-- Create `node` connected to every other node, and replicate a configuration adding it. -/
@[extern "cft_trust_node"]
opaque trustNode (term : @& Term) (node : @& NodeId) : IO Unit

/-- Create `nodes` connected to every other node, and replicate a configuration adding them. -/
@[extern "cft_trust_nodes"]
opaque trustNodes (term : @& Term) (nodes : @& List NodeId) : IO Unit

/-- Replicate a configuration which removes `retire` and adds the new node `trust`. -/
@[extern "cft_swap_node"]
opaque swapNode (term : @& Term) (retire trust : @& NodeId) : IO Unit

/-- Replicate a configuration which removes `retire` and adds the new nodes `trust`. -/
@[extern "cft_swap_nodes"]
opaque swapNodes (term : @& Term) (retire : @& List NodeId := [])
    (trust : @& List NodeId := []) : IO Unit

/-- Replicate that the retirement of `nodes` is committed. -/
@[extern "cft_cleanup_nodes"]
opaque cleanupNodes (term : @& Term) (nodes : @& List NodeId) : IO Unit

/-- Ask `node` to nominate a successor. -/
@[extern "cft_nominate_successor"]
opaque nominateSuccessor (node : @& NodeId) : IO Unit

/-- Create nodes `ids` with an initial configuration which is not replicated. Deprecated. -/
@[extern "cft_nodes"]
opaque nodes (ids : @& List NodeId) : IO Unit

/-- Create `node` without adding it to a configuration. Deprecated. -/
@[extern "cft_create_new_node"]
opaque createNewNode (node : @& NodeId) : IO Unit

/-- Replicate a configuration of `nodes`, creating those which do not exist. Deprecated. -/
@[extern "cft_replicate_new_configuration"]
opaque replicateNewConfiguration (term : @& Term) (nodes : @& List NodeId) : IO Unit

/-! ## Replication -/

/-- The entry of a `replicate` batch which is a signature, and so committable. -/
def signature : Text := "$"

/--
Replicate `entries` in one batch on the primary in `term`.
Each entry is `signature`, or the data of a transaction.
-/
@[extern "cft_replicate"]
opaque replicate (term : @& Term) (entries : @& List Text) : IO Unit

/-! ## Time -/

/-- Advance the clock of `node` by `ms` milliseconds. -/
@[extern "cft_periodic_one"]
opaque periodicOne (node : @& NodeId) (ms : UInt64) : IO Unit

/-- Advance the clock of every node by `ms` milliseconds. -/
@[extern "cft_periodic_all"]
opaque periodicAll (ms : UInt64) : IO Unit

/-! ## Network -/

/-- Connect `first` and `second`. -/
@[extern "cft_connect"]
opaque connect (first second : @& NodeId) : IO Unit

/-- Disconnect `first` and `second`; messages between them are dropped on dispatch. -/
@[extern "cft_disconnect"]
opaque disconnect (first second : @& NodeId) : IO Unit

/-- Disconnect `node` from every other node. -/
@[extern "cft_disconnect_node"]
opaque disconnectNode (node : @& NodeId) : IO Unit

/-- Reconnect `first` and `second`. -/
@[extern "cft_reconnect"]
opaque reconnect (first second : @& NodeId) : IO Unit

/-- Reconnect `node` to every other node. -/
@[extern "cft_reconnect_node"]
opaque reconnectNode (node : @& NodeId) : IO Unit

/-- Deliver the messages sent by `node` until it has none left. -/
@[extern "cft_dispatch_one"]
opaque dispatchOne (node : @& NodeId) : IO Unit

/-- Deliver the oldest message sent by `source` to `target`. -/
@[extern "cft_dispatch_single"]
opaque dispatchSingle (source target : @& NodeId) : IO Unit

/-- Deliver the messages already sent by every node, but not their responses. -/
@[extern "cft_dispatch_all_once"]
opaque dispatchAllOnce : IO Unit

/-- Repeat `dispatchAllOnce` until no messages remain, at most five times. -/
@[extern "cft_dispatch_all"]
opaque dispatchAll : IO Unit

/-- Drop the undelivered messages sent by `node`. -/
@[extern "cft_drop_pending"]
opaque dropPending (node : @& NodeId) : IO Unit

/-- Drop the undelivered messages sent by `source` to `target`. -/
@[extern "cft_drop_pending_to"]
opaque dropPendingTo (source target : @& NodeId) : IO Unit

/-- Shuffle the undelivered messages sent by `node`. -/
@[extern "cft_shuffle_one"]
opaque shuffleOne (node : @& NodeId) : IO Unit

/-- Shuffle the undelivered messages sent by each node. -/
@[extern "cft_shuffle_all"]
opaque shuffleAll : IO Unit

/-! ## Reporting -/

/-- Print the leadership, membership, last transaction and commit index of `node`. -/
@[extern "cft_state_one"]
opaque stateOne (node : @& NodeId) : IO Unit

/-- Print the leadership, membership, last transaction and commit index of every node. -/
@[extern "cft_state_all"]
opaque stateAll : IO Unit

/-- Print the ledger of `node`. -/
@[extern "cft_summarise_log"]
opaque summariseLog (node : @& NodeId) : IO Unit

/-- Print the ledger of every node. -/
@[extern "cft_summarise_logs_all"]
opaque summariseLogsAll : IO Unit

/-- Print the undelivered messages sent by `source` to `target`. -/
@[extern "cft_summarise_messages"]
opaque summariseMessages (source target : @& NodeId) : IO Unit

/-! ## Assertions -/

/-- Assert that every node has the same term, ledger and commit index. -/
@[extern "cft_assert_state_sync"]
opaque assertStateSync : IO Unit

/-- Assert that a quorum of each of its configurations holds what `node` has committed. -/
@[extern "cft_assert_commit_safety"]
opaque assertCommitSafety (node : @& NodeId) : IO Unit

/-- Assert that the commit index of `node` is `idx`. -/
@[extern "cft_assert_commit_idx"]
opaque assertCommitIdx (node : @& NodeId) (idx : UInt64) : IO Unit

/-- Assert that `node` reports `expected` for `detail`, a field of its consensus details. -/
@[extern "cft_assert_detail"]
opaque assertDetail (node : @& NodeId) (detail : @& String) (expected : @& Text) : IO Unit

/-- Assert that `node` does not report `unexpected` for `detail`. -/
@[extern "cft_assert_not_detail"]
opaque assertNotDetail (node : @& NodeId) (detail : @& String) (unexpected : @& Text)
    : IO Unit

/-- Assert that `node` has a configuration at `idx`, consisting of `nodes`. -/
@[extern "cft_assert_config"]
opaque assertConfig (node : @& NodeId) (idx : UInt64) (nodes : @& List NodeId) : IO Unit

/-- Assert that `node` has no configuration at `idx`. -/
@[extern "cft_assert_absent_config"]
opaque assertAbsentConfig (node : @& NodeId) (idx : UInt64) : IO Unit

/-- Assert that the last transaction in the ledger of `node` is `txid`, such as `"2.5"`. -/
@[extern "cft_assert_last_txid"]
opaque assertLastTxid (node : @& NodeId) (txid : @& String) : IO Unit

/-- Sign on the latest primary, reconnect the active nodes and run until they are in sync. -/
@[extern "cft_loop_until_sync"]
opaque loopUntilSync : IO Unit

/-! ## Running scenarios -/

/-- The registered scenarios, by name. -/
initialize scenarios : IO.Ref (List (String × IO Unit)) ← IO.mkRef []

/--
Register `steps` as the scenario `name`. Use as `initialize scenario "name" do ...`.
The scenario test runs the scenario named after each file in `Scenarios/`.
-/
def scenario (name : String) (steps : IO Unit) : IO Unit :=
  scenarios.modify ((name, steps) :: ·)

@[extern "cft_start"]
private opaque start (fluentd : @& List String) : IO Unit

@[extern "cft_finish"]
private opaque finish : IO Unit

/--
Run the scenario named by the first argument.
Any trace is exported to the Fluentd host and port given by the remaining arguments.
-/
def run (args : List String) : IO Unit := do
  let usage := "Expected a scenario name, optionally followed by a Fluentd host and port"
  let (name, fluentd) ←
    match args with
    | [name] => pure (name, [])
    | [name, host, port] => pure (name, [host, port])
    | _ => throw <| IO.userError usage
  let registered ← scenarios.get
  let known := registered.map (·.1) |>.reverse
  let some steps := registered.lookup name
  | throw <| IO.userError s!"Unknown scenario '{name}'. Known scenarios: {known}"
  start fluentd
  steps
  finish

end CftDriver
