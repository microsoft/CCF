import DisasterRecovery.Protocol.Model
import Lean.Data.Json
import Lean.Data.Json.FromToJson

namespace DisasterRecoveryTrace.Protocol.Trace

open DisasterRecovery.Protocol

open Lean

def contractVersion : String :=
  "ccf.recovery_decision_protocol.trace/1"

inductive Kind where
  | start
  | gossipAccepted
  | voteAccepted
  | iAmOpenAccepted
  | timeout
  | send
  | open
  | joinRestart
  | complete
deriving Repr, BEq, Inhabited

structure TraceEvent where
  version : String
  instanceId : String
  expectedLocations : List Location
  node : Location
  sequence : Nat
  kind : Kind
  messageId : Option String
  causedBy : Option String
  source : Option Location
  txid : Option TxID
  pre : Option Phase
  post : Option Phase
  openKind : Option OpenKind
  send : Option String
deriving Repr, BEq, Inhabited

private def parseKind : String -> Except String Kind
  | "start" => pure .start
  | "gossip_accepted" => pure .gossipAccepted
  | "vote_accepted" => pure .voteAccepted
  | "iamopen_accepted" => pure .iAmOpenAccepted
  | "timeout" => pure .timeout
  | "send" => pure .send
  | "open" => pure .open
  | "join_restart" => pure .joinRestart
  | "complete" => pure .complete
  | value => throw s!"unknown kind '{value}'"

private def parsePhase : String -> Except String Phase
  | "GOSSIPING" => pure .gossiping
  | "VOTING" => pure .voting
  | "OPENING" => pure .opening
  | "JOINING" => pure .joining
  | "OPEN" => pure .open
  | value => throw s!"unknown phase '{value}'"

private def parseOpenKind : String -> Except String OpenKind
  | "QUORUM" => pure .quorum
  | "FAILOVER" => pure .failover
  | value => throw s!"unknown open kind '{value}'"

private def optionalString (json : Json) (key : String) :
    Except String (Option String) :=
  match json.getObjVal? key with
  | .error _ | .ok .null => pure none
  | .ok value => some <$> value.getStr?

private def optionalNat (json : Json) (key : String) :
    Except String (Option Nat) :=
  match json.getObjVal? key with
  | .error _ | .ok .null => pure none
  | .ok value => some <$> value.getNat?

private def optionalParsed
    (json : Json)
    (key : String)
    (parse : String -> Except String α) :
    Except String (Option α) := do
  match <- optionalString json key with
  | none => pure none
  | some value => some <$> parse value

def parseEvent (line : String) : Except String TraceEvent := do
  let json <- Json.parse line
  let version <- json.getObjValAs? String "version"
  if version != contractVersion then
    throw s!"unsupported version '{version}'"

  let view <- optionalNat json "view"
  let seqno <- optionalNat json "seqno"
  if view.isSome != seqno.isSome then
    throw "view and seqno must appear together"

  let instanceId <- json.getObjValAs? String "instance"
  let expectedLocations <-
    json.getObjValAs? (List String) "expected_locations"
  let node <- json.getObjValAs? String "node"
  let sequence <- json.getObjValAs? Nat "sequence"
  let kindName <- json.getObjValAs? String "kind"
  let kind <- parseKind kindName
  let messageId <- optionalString json "message_id"
  let causedBy <- optionalString json "caused_by"
  let source <- optionalString json "source"
  let pre <- optionalParsed json "pre" parsePhase
  let post <- optionalParsed json "post" parsePhase
  let openKind <- optionalParsed json "open_kind" parseOpenKind
  let send <- optionalString json "send"
  pure {
    version
    instanceId
    expectedLocations
    node
    sequence
    kind
    messageId
    causedBy
    source
    txid := match view, seqno with
      | some view, some seqno => some { view, seqno }
      | _, _ => none
    pre
    post
    openKind
    send
  }

def parseNDJSON (input : String) : Except String (List TraceEvent) := do
  let lines := (input.splitOn "\n").filter
    (fun line => !line.trimAscii.isEmpty)
  let mut events := []
  for (line, index) in lines.zipIdx do
    match parseEvent line with
    | .ok event => events := event :: events
    | .error message => throw s!"line {index + 1}: {message}"
  pure events.reverse

end DisasterRecoveryTrace.Protocol.Trace
