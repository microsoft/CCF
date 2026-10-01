import DisasterRecovery.Replay

set_option autoImplicit false

/-!
Extracts recovery-decision-protocol records from CCF node logs, and checks
each against the fields its kind carries. Nodes started with the
`CCF_RECOVERY_TRACE` environment variable set log each record as `RDP_TRACE`
followed by a JSON object, and log `Failed to trace recovery-decision-protocol`
when they cannot.
-/

namespace DisasterRecovery.Replay

open Lean Model.Local

/-- Why a trace is not accepted. -/
inductive Failure where
  /-- Evidence that the reduction rules reject. -/
  | invalid (message : String)
  /-- Evidence that logs which are still growing may yet complete. -/
  | incomplete (message : String)

abbrev Checked :=
  Except Failure

def require (condition : Bool) (message : String) : Checked Unit :=
  unless condition do
    throw (.invalid message)

/-- One record, and the log line it is on. -/
structure Record where
  file : String
  line : Nat
  value : Json
deriving Inhabited

def Record.location (record : Record) : String :=
  s!"{record.file}:{record.line}"

def marker : String :=
  "RDP_TRACE "

/-- `trace_safely` logs this when it cannot emit a record. -/
def failureMarker : String :=
  "Failed to trace recovery-decision-protocol"

/-- The records on the lines of one log. -/
def parseLog (file : String) (lines : List String) : Checked (Array Record) := do
  let mut records := #[]
  for text in lines, line in [1:lines.length + 1] do
    let location := s!"{file}:{line}"
    if text.contains failureMarker then
      throw (.invalid s!"{location}: the node failed to trace: {text}")
    if let _ :: first :: rest := text.splitOn marker then
      match Json.parse (marker.intercalate (first :: rest)) with
      | .ok value@(.obj _) => records := records.push { file, line, value }
      | .ok _ => throw (.invalid s!"{location}: expected a JSON object")
      | .error error => throw (.invalid s!"{location}: {error}")
  return records

/-- The records of a log that may still be growing. Only whole lines are read. -/
def readLog (path : System.FilePath) : IO (Checked (Array Record)) := do
  let data ← IO.FS.readBinFile path
  let mut lines := 0
  let mut complete := 0
  for index in [:data.size] do
    if data[index]! == 10 then
      lines := lines + 1
      complete := index + 1
  if complete < data.size then
    return .error (.incomplete s!"{path}:{lines + 1}: unterminated log line")
  let some text := String.fromUTF8? (data.extract 0 complete)
  | return .error (.invalid s!"{path}: invalid UTF-8")
  return parseLog path.toString (text.splitOn "\n").dropLast

/-- Every record of the given logs, in log order. -/
def readLogs (paths : List System.FilePath) : IO (Checked (Array Record)) := do
  let mut records := #[]
  for path in paths do
    match ← readLog path with
    | .ok more => records := records ++ more
    | .error failure => return .error failure
  if records.isEmpty then
    return .error (.incomplete "no recovery-decision-protocol trace records found")
  return .ok records

/--
What `advance()` read and wrote in a handler or timeout execution that
committed, with the TxID seqno CCF reported for its transaction: the version
it committed at if it wrote, and the version it read at otherwise.
-/
structure Execution where
  pre : Phase
  preTimeout : Phase
  post : Phase
  postTimeout : Phase
  version : Nat
  wrote : Bool
  gossips : Option (List (Location × TxID))
  votes : Option (List Location)
  chosen : Option Location
  openKind : Option OpenKind
  restart : Bool
deriving Inhabited, BEq

inductive Body where
  | start (version : Nat) (expectedLocations : List Location)
  | send (batch : Nat) (target : Location) (message : Message) (preVersion : Nat)
  | timeout (execution : Execution)
  | receive (source : Location) (message : Message) (causedBy : Option (Location × Nat))
    (execution : Execution)
deriving Inhabited

/-- One validated record, in the model's vocabulary. -/
structure TraceEvent where
  record : Record
  node : Location
  sequence : Nat
  body : Body
deriving Inhabited

def messageName : Message → String
  | .gossip _ => "gossip"
  | .vote => "vote"
  | .iAmOpen => "iAmOpen"

def TraceEvent.kind (event : TraceEvent) : String :=
  match event.body with
  | .start .. => "start"
  | .send .. => "send"
  | .timeout .. => "timeout"
  | .receive _ (.gossip _) _ _ => "gossip_accepted"
  | .receive _ .vote _ _ => "vote_accepted"
  | .receive _ .iAmOpen _ _ => "iamopen_accepted"

/-- The send record that caused a receive. -/
def TraceEvent.causedBy? (event : TraceEvent) : Option (Location × Nat) :=
  match event.body with
  | .receive _ _ causedBy _ => causedBy
  | _ => none

def TraceEvent.isIAmOpen (event : TraceEvent) : Bool :=
  event.body matches .receive _ .iAmOpen _ _

/-- The model action of a timeout or receive, and what it recorded. -/
def TraceEvent.execution? (event : TraceEvent) : Option (Model.Action × Execution) :=
  match event.body with
  | .timeout execution => some (.local event.node .timeout, execution)
  | .receive source message _ execution =>
      some (.deliver { source, target := event.node, payload := message }, execution)
  | _ => none

def TraceEvent.origin (event : TraceEvent) (rule : String) : Origin :=
  { file := event.record.file, line := event.record.line, rule }

private def common : List String :=
  ["node", "sequence", "kind"]

private def executionFields : List String :=
  common ++ ["pre", "pre_timeout", "post", "post_timeout", "version", "wrote"]

private def advanceFields : List String :=
  ["gossips", "votes", "chosen", "open_kind", "restart"]

/-- The required and optional fields of each record kind. -/
private def fieldsOf : String → Option (List String × List String)
  | "start" => some (common ++ ["version", "expected_locations"], [])
  | "send" => some (common ++ ["batch", "send", "pre_version"], ["txid"])
  | "timeout" => some (executionFields, advanceFields)
  | "gossip_accepted" =>
      some (executionFields ++ ["source", "txid"], advanceFields ++ ["caused_by"])
  | "vote_accepted"
  | "iamopen_accepted" =>
      some (executionFields ++ ["source"], advanceFields ++ ["caused_by"])
  | _ => none

private def digits (text : String) : Option Nat :=
  if !text.isEmpty && text.all Char.isDigit then text.toNat? else none

private def parseNatural (location : String) : Json → Checked Nat
  | .num { mantissa := .ofNat value, exponent := 0 } => pure value
  | _ => throw (.invalid s!"{location}: expected natural number")

private def parseName (location : String) (value : Json) : Checked Location := do
  let .str text := value | throw (.invalid s!"{location}: expected location name")
  require (!text.isEmpty) s!"{location}: expected location name"
  return text

private def parsePhase (location : String) : Json → Checked Phase
  | .str "Gossiping" => pure .gossiping
  | .str "Voting" => pure .voting
  | .str "Opening" => pure .opening
  | .str "Joining" => pure .joining
  | .str "Open" => pure .open
  | value => throw (.invalid s!"{location}: unknown phase {value.compress}")

/-- TxIDs are "view.seqno" strings. -/
private def parseTxID (location : String) (value : Json) : Checked TxID := do
  let invalid := Failure.invalid s!"{location}: invalid TxID {value.compress}"
  let .str text := value | throw invalid
  let [view, seqno] := text.splitOn "." | throw invalid
  let some view := digits view | throw invalid
  let some seqno := digits seqno | throw invalid
  return { view, seqno }

/-- `caused_by` is NODE:SEQUENCE. The node name may contain ':'. -/
private def parseCause (location : String) (value : Json) : Checked (Location × Nat) := do
  let invalid := Failure.invalid s!"{location}: invalid caused_by {value.compress}"
  let .str text := value | throw invalid
  let parts := text.splitOn ":"
  let node := ":".intercalate parts.dropLast
  let some sequence := digits (parts.getLastD "") | throw invalid
  if node.isEmpty then throw invalid
  return (node, sequence)

/-- Validates one record against the fields its kind carries. -/
def parseEvent (record : Record) : Checked TraceEvent := do
  let value := record.value
  let location := record.location
  let fields : List String :=
    match value with
    | .obj entries => entries.toList.map fun (key, _) => key
    | _ => []
  let kind := value.getObjValD "kind"
  let some (required, optional) :=
    (match kind with
      | .str name => fieldsOf name
      | _ => none)
  | throw (.invalid s!"{location}: unknown record kind {kind.compress}")
  let kind := kind.getStr?.toOption.getD ""
  let missing := required.filter (!fields.contains ·)
  require missing.isEmpty s!"{location}: {kind} misses {missing.mergeSort}"
  let unknown := fields.filter fun key => !required.contains key && !optional.contains key
  require unknown.isEmpty s!"{location}: {kind} has unknown fields {unknown}"
  let get (key : String) : Json := value.getObjValD key
  let optionalField {α : Type} (key : String) (parse : Json → Checked α)
      : Checked (Option α) :=
    if fields.contains key then some <$> parse (get key) else pure none
  let node ← parseName location (get "node")
  let sequence ← parseNatural location (get "sequence")
  let pre ← optionalField "pre" (parsePhase location)
  let preTimeout ← optionalField "pre_timeout" (parsePhase location)
  let post ← optionalField "post" (parsePhase location)
  let postTimeout ← optionalField "post_timeout" (parsePhase location)
  let gossips ←
    optionalField "gossips"
      fun
      | .obj entries =>
          entries.toList.mapM
            fun (key, item) => do
              return (← parseName location (.str key), ← parseTxID location item)
      | _ => throw (.invalid s!"{location}: invalid gossips")
  let votes ←
    optionalField "votes"
      fun
      | .arr items => do
          let names ← items.toList.mapM (parseName location)
          require (names.eraseDups.length == names.length) s!"{location}: duplicate votes"
          return names.mergeSort
      | _ => throw (.invalid s!"{location}: invalid votes")
  let chosen ← optionalField "chosen" (parseName location)
  let openKind ←
    optionalField "open_kind"
      fun
      | .str "Quorum" => pure OpenKind.quorum
      | .str "Failover" => pure OpenKind.failover
      | _ => throw (.invalid s!"{location}: invalid open_kind")
  let restart ←
    optionalField "restart"
      fun
      | .bool flag => pure flag
      | _ => throw (.invalid s!"{location}: invalid restart")
  let restart := restart.getD false
  let source ← optionalField "source" (parseName location)
  let causedBy ← optionalField "caused_by" (parseCause location)
  let txid ← optionalField "txid" (parseTxID location)
  let batch ← optionalField "batch" (parseNatural location)
  let natural (key : String) : Checked Nat := parseNatural location (get key)
  let event (body : Body) : TraceEvent := { record, node, sequence, body }
  if kind == "start" then
    let .arr expected := get "expected_locations"
    | throw (.invalid s!"{location}: invalid expected_locations")
    return event
      (.start (← natural "version") (← expected.toList.mapM (parseName location)))
  if kind == "send" then
    let send := get "send"
    let invalid := Failure.invalid s!"{location}: invalid send {send.compress}"
    let .str text := send | throw invalid
    let sendKind :: rest@(_ :: _) := text.splitOn ":" | throw invalid
    let target := ":".intercalate rest
    if target.isEmpty then throw invalid
    let message ←
      match sendKind, txid with
      | "gossip", some txid => pure (Message.gossip txid)
      | "vote", none => pure .vote
      | "iamopen", none => pure .iAmOpen
      | "gossip", none
      | "vote", some _
      | "iamopen", some _ =>
          throw (.invalid s!"{location}: only gossip sends carry a txid")
      | _, _ => throw invalid
    let some batch := batch | throw (.invalid s!"{location}: send misses batch")
    return event (.send batch target message (← natural "pre_version"))
  let (some pre, some preTimeout, some post, some postTimeout) :=
    (pre, preTimeout, post, postTimeout)
  | throw (.invalid s!"{location}: {kind} misses its phases")
  let .bool wrote := get "wrote" | throw (.invalid s!"{location}: invalid wrote")
  let execution : Execution :=
    {
      pre,
      preTimeout,
      post,
      postTimeout,
      version := ← natural "version",
      wrote,
      gossips,
      votes,
      chosen,
      openKind,
      restart
    }
  -- advance() records the maps it evaluates, the node it chooses or joins,
  -- the open kind it writes and the restart it requests.
  let advanced := if kind == "iamopen_accepted" then Phase.joining else pre
  for (key, present)
      in [
        ("gossips", advanced == .gossiping),
        ("votes", advanced == .voting),
        ("chosen", advanced == .joining || (advanced == .gossiping && post == .voting)),
        ("open_kind", advanced == .voting && post == .opening)
      ] do
    require (fields.contains key == present)
      s!"{location}: {kind} from {phaseName pre} to {phaseName post} {if present then "must" else "cannot"} record {key}"
  if kind == "timeout" then
    return event (.timeout execution)
  let some source := source | throw (.invalid s!"{location}: {kind} misses source")
  let message ←
    match kind, txid with
    | "gossip_accepted", some txid =>
        pure (Message.gossip txid)
    | "vote_accepted", _ => pure .vote
    | "iamopen_accepted", _ =>
        -- IAmOpen writes Joining and its sender as the chosen node before advance().
        require (pre == .joining && post == .joining && chosen == some source)
          s!"{location}: IAmOpen does not record its Joining write"
        pure .iAmOpen
    | _, _ => throw (.invalid s!"{location}: {kind} misses txid")
  return event (.receive source message causedBy execution)

end DisasterRecovery.Replay
