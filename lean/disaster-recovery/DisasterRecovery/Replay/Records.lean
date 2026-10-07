import DisasterRecovery.Replay
import Lean.Data.Json

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
  chosen : Option Location
  openKind : Option OpenKind
  restart : Bool
deriving Inhabited

inductive Body where
  | start (version : Nat) (expectedLocations : List Location)
  | send (batch : Nat) (target : Location) (message : Message) (preVersion : Nat)
  | timeout (execution : Execution)
  | receive (source : Location) (message : Message) (execution : Execution)
deriving Inhabited

/-- One validated record, in the model's vocabulary. -/
structure TraceEvent where
  record : Record
  node : Location
  sequence : Nat
  body : Body
deriving Inhabited

def TraceEvent.isIAmOpen (event : TraceEvent) : Bool :=
  event.body matches .receive _ .iAmOpen _

/-- The model action of a timeout or receive, and what it recorded. -/
def TraceEvent.execution? (event : TraceEvent) : Option (Model.Action × Execution) :=
  match event.body with
  | .timeout execution => some (.local event.node .timeout, execution)
  | .receive source message execution =>
      some (.deliver { source, target := event.node, payload := message }, execution)
  | _ => none

def TraceEvent.origin (event : TraceEvent) (rule : String) : Origin :=
  { file := event.record.file, line := event.record.line, rule }

private def common : List String :=
  ["node", "sequence", "kind"]

private def executionFields : List String :=
  common ++ ["pre", "pre_timeout", "post", "post_timeout", "version"]

private def advanceFields : List String :=
  ["chosen", "open_kind", "restart"]

/-- The required and optional fields of each record kind. -/
private def fieldsOf : String → Option (List String × List String)
  | "start" => some (common ++ ["version", "expected_locations"], [])
  | "send" => some (common ++ ["batch", "message", "target", "pre_version"], ["txid"])
  | "timeout" => some (executionFields, advanceFields)
  | "gossip_accepted" => some (executionFields ++ ["source", "txid"], advanceFields)
  | "vote_accepted"
  | "iamopen_accepted" => some (executionFields ++ ["source"], advanceFields)
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

/-- Validates one record against the fields its kind carries. -/
def parseEvent (record : Record) : Checked TraceEvent := do
  let value := record.value
  let location := record.location
  let invalid (what : String) : Failure := .invalid s!"{location}: {what}"
  let fields : List String :=
    match value with
    | .obj entries => entries.toList.map fun (key, _) => key
    | _ => []
  let kind := (value.getObjValD "kind").getStr?.toOption.getD ""
  let some (required, optional) := fieldsOf kind
  | throw (invalid s!"unknown record kind {(value.getObjValD "kind").compress}")
  let missing := required.filter (!fields.contains ·)
  require missing.isEmpty s!"{location}: {kind} misses {missing.mergeSort}"
  let unknown := fields.filter fun key => !required.contains key && !optional.contains key
  require unknown.isEmpty s!"{location}: {kind} has unknown fields {unknown}"
  -- Every required field is present from here on.
  let get (key : String) : Json := value.getObjValD key
  let ifPresent {α : Type} (key : String) (parse : Json → Checked α)
      : Checked (Option α) :=
    if fields.contains key then some <$> parse (get key) else pure none
  let natural (key : String) := parseNatural location (get key)
  let name (key : String) := parseName location (get key)
  let phase (key : String) := parsePhase location (get key)
  let event (body : Body) : Checked TraceEvent := do
    return { record, node := ← name "node", sequence := ← natural "sequence", body }
  match kind with
  | "start" =>
      let .arr expected := get "expected_locations"
      | throw (invalid "invalid expected_locations")
      event (.start (← natural "version") (← expected.toList.mapM (parseName location)))
  | "send" =>
      let message ←
        match get "message", ← ifPresent "txid" (parseTxID location) with
        | .str "gossip", some txid => pure (Message.gossip txid)
        | .str "vote", none => pure .vote
        | .str "iamopen", none => pure .iAmOpen
        | message, _ =>
            throw
              (invalid
                s!"invalid message {message.compress}, or a txid on one that is not gossip")
      event
        (.send (← natural "batch") (← name "target") message (← natural "pre_version"))
  | _ =>
      let pre ← phase "pre"
      let post ← phase "post"
      let preTimeout ← phase "pre_timeout"
      let postTimeout ← phase "post_timeout"
      -- Votes and IAmOpens always write: a vote is a Set::insert, and an
      -- IAmOpen puts Joining and the chosen node. Any other write the
      -- replayer can observe changes a phase. A write that changes no
      -- phase, such as storing a new gossip or node info, is not
      -- observable here, so treating it as a read changes nothing.
      let wrote :=
        kind == "vote_accepted"
        || kind == "iamopen_accepted"
        || pre != post
        || preTimeout != postTimeout
      let openKind ←
        ifPresent "open_kind"
          fun
          | .str "Quorum" => pure OpenKind.quorum
          | .str "Failover" => pure OpenKind.failover
          | _ => throw (invalid "invalid open_kind")
      let restart ←
        ifPresent "restart"
          fun
          | .bool flag => pure flag
          | _ => throw (invalid "invalid restart")
      let chosen ← ifPresent "chosen" (parseName location)
      let execution : Execution :=
        {
          pre,
          preTimeout,
          post,
          postTimeout,
          version := ← natural "version",
          wrote,
          chosen,
          openKind,
          restart := restart.getD false
        }
      -- The replay only compares the fields that a record has. On the move to
      -- Voting, only `chosen` shows the node that advance() chose.
      require (fields.contains "chosen" || !(pre == .gossiping && post == .voting))
        s!"{location}: {kind} moves to voting without recording the chosen node"
      match kind with
      | "timeout" => event (.timeout execution)
      | "gossip_accepted" =>
          event
            (.receive (← name "source") (.gossip (← parseTxID location (get "txid")))
              execution)
      | "vote_accepted" => event (.receive (← name "source") .vote execution)
      | _ =>
          -- IAmOpen writes Joining before advance() runs, so its `pre` is that
          -- write, which the replay does not compare with the model.
          require (pre == .joining)
            s!"{location}: IAmOpen does not record its Joining write"
          event (.receive (← name "source") .iAmOpen execution)

end DisasterRecovery.Replay
