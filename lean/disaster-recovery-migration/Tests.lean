import DisasterRecoveryMigration.Legacy.Model

open DisasterRecoveryMigration.Legacy

private def expect (condition : Bool) (message : String) : IO Unit :=
  unless condition do throw (IO.userError message)

private def deliverByKey (n : Nat) (state : GlobalState) (key : String) : Option GlobalState := do
  let action <- (actions state).find? (fun action => actionKey action == key)
  nextState n state action

def main : IO UInt32 := do
  let single := initialState 1
  expect (single.actors[0]!.nextStep == .open false)
    "single node did not open immediately without timeout"

  let initial3 := initialState 3
  let timed <- match nextState 3 initial3 (.timeout 0) with
    | some state => pure state
    | none => throw (IO.userError "node 0 timeout was suppressed")
  expect (timed.actors[0]!.nextStep == .open true)
    "timeout did not drive vote and open-join closure to timeout-open"

  let opened := timed.actors[0]!
  let lateGossip : Gossip := { src := 2, txid := 2 }
  let frozen <- match onMessage 3 0 opened (.gossip lateGossip) with
    | some result => pure result
    | none => throw (IO.userError "message callback was unexpectedly suppressed")
  expect (frozen.1.gossips == opened.gossips)
    "gossip collection changed after the vote was submitted"

  let joinActor : ActorState := {
    nextStep := .openJoin
    gossips := [{ src := 1, txid := 1 }]
    votes := []
    submittedVote := none
    txid := 1
  }
  let joined <- match onMessage 3 1 joinActor (.iAmOpen 0) with
    | some result => pure result
    | none => throw (IO.userError "IAmOpen was suppressed")
  expect (joined.1.nextStep == .join) "IAmOpen did not cause Join"

  let firstOrder <- match deliverByKey 3 initial3 "deliver(1,0,g(1,1))" with
    | some state => pure state
    | none => throw (IO.userError "first unordered delivery failed")
  let firstOrder <- match deliverByKey 3 firstOrder "deliver(2,0,g(2,2))" with
    | some state => pure state
    | none => throw (IO.userError "second unordered delivery failed")
  let secondOrder <- match deliverByKey 3 initial3 "deliver(2,0,g(2,2))" with
    | some state => pure state
    | none => throw (IO.userError "reverse first unordered delivery failed")
  let secondOrder <- match deliverByKey 3 secondOrder "deliver(1,0,g(1,1))" with
    | some state => pure state
    | none => throw (IO.userError "reverse second unordered delivery failed")
  expect (firstOrder == secondOrder) "unordered deliveries produced different states"

  let duplicate : Envelope := { src := 1, dst := 0, msg := .gossip { src := 1, txid := 1 } }
  let duplicated := { initial3 with network := duplicate :: duplicate :: initial3.network }
  let once <- match nextState 3 duplicated (.deliver duplicate) with
    | some state => pure state
    | none => throw (IO.userError "first duplicate delivery was suppressed")
  expect (once.network.count duplicate + 1 == duplicated.network.count duplicate)
    "delivery did not remove exactly one duplicate"
  let twice <- match nextState 3 once (.deliver duplicate) with
    | some state => pure state
    | none => throw (IO.userError "second duplicate delivery was suppressed")
  expect (twice.network.count duplicate + 1 == once.network.count duplicate)
    "second delivery did not remove exactly one duplicate"

  IO.println "all Lean semantic checks passed"
  pure 0
