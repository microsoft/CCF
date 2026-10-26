module

public import consistency.Model.History

@[expose] public section

namespace consistency.Model

/-- Extend the externally visible history by one event. -/
def appendEvent (state : State) (event : Event) : State :=
  { state with history := state.history ++ [event] }

/-- Extend a branch after the caller has checked its one-based index. -/
def appendEntry (state : State) (branch : Nat) (entry : Entry) : State :=
  { state with branches := state.branches.modify (branch - 1) (· ++ [entry]) }

/-- Branches eligible for election retain all known committed entries. -/
def hasCommittedPrefix (state : State) (branch : List Entry) : Bool :=
  let frontier := commitSeqno state.history
  frontier ≤ branch.length
  && (frontier = 0
      || (match at? branch frontier with
          | some entry =>
              (statusIDs state.history .committed).contains ⟨entry.view, frontier⟩
          | none => false))

/-- A transaction can be declared invalid under three alternatives.
The commit frontier has passed this position with a different transaction, or a
higher view has committed below this position, or the current-view suffix is
declared invalid before the frontier reaches it.
The last alternative permits invalid reports before commit knowledge catches up;
`commit` must correspondingly exclude that suffix. -/
def mayInvalidate (state : State) (txid : TxID) : Bool :=
  let frontier := commitSeqno state.history
  match state.branches.getLast? with
  | none => false
  | some latest =>
      (frontier ≥ txid.seqno
        && (match at? latest txid.seqno with
            | some entry => entry.view != txid.view
            | none => false))
      || (frontier > 0
          && frontier < txid.seqno
          && (match at? latest frontier with
              | some entry => entry.view > txid.view
              | none => false))
      || (txid.view = state.branches.length && txid.seqno > frontier)

/-- Submit a transaction request with the next shared request ID. -/
def request (config : Config) (state : State) (kind : TxType) : Option State := do
  guard (kind = .rw || config.reads)
  return appendEvent state (.request kind (nextRequestId state.history))

/-- Execute a previously unexecuted write on an eligible branch.
Any eligible branch may be selected, not just the newest: the request can be
picked up by the current leader or a former leader. -/
def execute (config : Config) (state : State) (requestIndex branch : Nat)
    : Option State := do
  let .request .rw tx ← at? state.history requestIndex | none
  guard (activeBranch config state branch)
  guard (!(state.branches.any fun ledger => ledger.any fun entry => entry.tx == some tx))
  return appendEntry state branch ⟨branch, some tx⟩

/-- Respond to an executed write with its observed prefix and transaction ID. -/
def respond (config : Config) (state : State) (requestIndex branch seqno : Nat)
    : Option State := do
  let .request .rw tx ← at? state.history requestIndex | none
  guard (!responded state.history requestIndex .rw tx)
  guard (activeBranch config state branch)
  let ledger ← at? state.branches branch
  let entry ← at? ledger seqno
  guard (entry.tx == some tx)
  return appendEvent state
    (.response .rw tx (writes (ledger.take seqno)) ⟨entry.view, seqno⟩)

/-- Execute and respond to a read-only request on a nonempty eligible branch.
Reads are always forwarded; unlike writes, execution and response are one action. -/
def read (config : Config) (state : State) (requestIndex branch : Nat)
    : Option State := do
  guard config.reads
  let .request .ro tx ← at? state.history requestIndex | none
  guard (!responded state.history requestIndex .ro tx)
  guard (activeBranch config state branch)
  let ledger ← at? state.branches branch
  let entry ← ledger.getLast?
  return appendEvent state (.response .ro tx (writes ledger) ⟨entry.view, ledger.length⟩)

/-- Report commitment when the newest branch and prior invalid statuses permit it. -/
def commit (state : State) (responseIndex : Nat) : Option State := do
  let .response .rw _ _ txid ← at? state.history responseIndex | none
  let latest ← state.branches.getLast?
  let entry ← at? latest txid.seqno
  guard (entry.view == txid.view)
  -- An earlier invalid report excludes the same-view suffix, even if it is still
  -- present in the newest branch.
  guard
    (!((statusIDs state.history .invalid).any
        fun invalid =>
          invalid.view == txid.view && invalid.seqno ≤ txid.seqno))
  -- Copied entries retain their original views, including across elections.
  guard
    (!((statusIDs state.history .invalid).any
        fun invalid =>
          invalid.seqno ≤ txid.seqno
          && match at? latest invalid.seqno with
              | some predecessor => predecessor.view == invalid.view
              | none => false))
  return appendEvent state (.status txid .committed)

/-- Report an invalid write in the multi-node model. -/
def invalidate (config : Config) (state : State) (responseIndex : Nat)
    : Option State := do
  guard config.multiNode
  let .response .rw _ _ txid ← at? state.history responseIndex | none
  guard (mayInvalidate state txid)
  return appendEvent state (.status txid .invalid)

/-- Append a transaction that does not affect the dummy application. -/
def appendOther (config : Config) (state : State) (branch : Nat) : Option State := do
  guard (activeBranch config state branch)
  return appendEntry state branch ⟨branch, none⟩

/-- Elect a new leader by copying a committed-prefix-compatible branch prefix.
This simulates rollback of uncommitted transactions and a view change without
overwriting the old leader's abstract ledger branch. -/
def elect (config : Config) (state : State) (branch prefixLength : Nat)
    : Option State := do
  guard config.multiNode
  let ledger ← at? state.branches branch
  guard (hasCommittedPrefix state ledger)
  guard (commitSeqno state.history ≤ prefixLength && prefixLength ≤ ledger.length)
  return { state with branches := state.branches ++ [ledger.take prefixLength] }

/-- Dispatch an action to its guarded transition; `none` means the action is disabled. -/
def step (config : Config) (state : State) (action : Action) : Option State :=
  match action with
  | .request kind => request config state kind
  | .execute requestIndex branch => execute config state requestIndex branch
  | .respond requestIndex branch seqno => respond config state requestIndex branch seqno
  | .read requestIndex branch => read config state requestIndex branch
  | .commit responseIndex => commit state responseIndex
  | .invalidate responseIndex => invalidate config state responseIndex
  | .appendOther branch => appendOther config state branch
  | .elect branch prefixLength => elect config state branch prefixLength

end consistency.Model
