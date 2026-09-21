import DisasterRecovery.Shared.Global

namespace DisasterRecovery.Tests.Network

open Shared

private inductive Input where
  | receive (source message : Nat)
  | increment
  | blocked
  | burst

private def protocol : Global.Protocol Nat Nat Input Nat Input where
  init _ state := state = 0
  step host _ state action := do
    match action with
    | .receive source message =>
        guard (message != 0)
        guard (message != 99)
        pure do
          host.send 1 source
          return state + message
    | .increment => pure (pure (state + 1))
    | .blocked => none
    | .burst => pure do
        host.send 1 0
        host.send 2 0
        return state + 1
  receive := .receive
  internal := id

example (host : Capabilities σ Nat Nat) (node state : Nat) :
    protocol.step host node state .blocked = none := rfl

private def initial : Global.State Nat Nat Nat := {
  nodes := [(0, 0), (1, 0)]
  active := [0, 1]
}

private def expect (condition : Bool) (message : String) : IO Unit :=
  unless condition do throw (IO.userError message)

private def requireSome (value : Option α) (message : String) : IO α :=
  match value with
  | some result => pure result
  | none => throw (IO.userError message)

def run : IO Unit := do
  let machine := Global.lift [0, 1] protocol
  let message : Global.Envelope Nat Nat := { source := 0, target := 1, payload := 5 }
  let reply : Global.Envelope Nat Nat := { source := 1, target := 0, payload := 1 }
  let queued := { initial with network := [message, message] }
  let delivered <- requireSome (machine.step queued (.deliver message))
    "generic delivery unexpectedly disabled"
  expect (Global.nodeState delivered 1 == some 5 && Global.nodeState delivered 0 == some 0)
    "delivery failed to update exactly its receiver"
  expect (delivered.network == [message, reply])
    "delivery must consume one occurrence and append its reply atomically"
  expect ((machine.step initial (.deliver message)).isNone)
    "delivery fabricated a queued message"
  expect ((machine.step { queued with active := [0] } (.deliver message)).isNone)
    "inactive receiver accepted a message"

  let blocked : Global.Envelope Nat Nat := { message with payload := 0 }
  expect
    ((machine.step { initial with network := [blocked] } (.deliver blocked)).isNone)
    "a disabled local receive consumed a message"
  let blockedSend : Global.Envelope Nat Nat := { message with payload := 99 }
  expect
    ((machine.step { initial with network := [blockedSend] } (.deliver blockedSend)).isNone)
    "a disabled receive produced a successor"
  expect ((machine.step initial (.local 1 .blocked)).isNone)
    "a disabled internal action produced a successor"

  let burst <- requireSome (machine.step queued (.local 1 .burst))
    "enabled send burst was disabled"
  expect (Global.nodeState burst 1 == some 1 &&
      burst.network == [message, message, reply, { reply with payload := 2 }])
    "mutable sends were reordered, lost, or executed more than once"

  let synthetic <- requireSome (machine.step queued (.local 1 (.receive 0 5)))
    "generic network disallowed a synthetic local receive"
  expect (Global.nodeState synthetic 1 == some 5)
    "synthetic receive failed to update local state"
  expect (synthetic.network == [message, message, reply])
    "synthetic receive removed a queued message"
  let isolated := { queued with nodes := [(1, 0)], active := [1] }
  let isolatedSent <- requireSome (machine.step isolated (.local 1 (.receive 0 5)))
    "sending to an absent node disabled the local step"
  expect (Global.nodeState isolatedSent 1 == Global.nodeState synthetic 1 &&
      isolatedSent.network == synthetic.network)
    "other nodes influenced a local step or its sends"
  expect ((machine.step isolatedSent (.deliver reply)).isNone)
    "an absent recipient accepted a queued message"
  let inactiveSent <- requireSome
    (machine.step { initial with active := [1] } (.local 1 (.receive 0 5)))
    "sending to an inactive node disabled the local step"
  expect (Global.nodeState inactiveSent 1 == Global.nodeState synthetic 1 &&
      inactiveSent.network == [reply])
    "recipient activity or the existing queue influenced a local step"
  let incremented <- requireSome (machine.step synthetic (.local 1 .increment))
    "internal increment disabled"
  expect (incremented.network == synthetic.network)
    "a later action replayed old outgoing messages"

  let self : Global.Envelope Nat Nat := { source := 0, target := 0, payload := 1 }
  let echoed <- requireSome
    (machine.step { initial with network := [self] } (.deliver self))
    "self-delivery disabled"
  expect (echoed.network == [self] && Global.nodeState echoed 0 == some 1)
    "a fresh identical reply was confused with the consumed occurrence"
  IO.println "generic network composition checks passed"

end DisasterRecovery.Tests.Network
