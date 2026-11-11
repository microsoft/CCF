-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import Tls.Model

@[expose] public section

/-!
The plaintext which the owners of two engines send and receive along an execution, and what
it means for something to be on its way to one of them.
-/

namespace Tls.Properties

open Tls.Model

/-- The plaintext a step accepts from the owner at `side`: a send to an open connection which
its queued output bound admits. -/
def accepted (config : Config) (state : Pair.State) (side : Pair.Side)
    : Pair.Action → List Payload
  | .send actor data =>
      if actor = side
          ∧ (state.conn side).alive
          ∧ admitsOutput config (state.conn side) data then
        data
      else
        []
  | _ => []

/-- The plaintext a step hands to the owner at `side`. -/
def delivered (config : Config) (state : Pair.State) (side : Pair.Side)
    (action : Pair.Action)
    : List Payload :=
  (Pair.deliveries config state side action).map (·.payload)

/-- What the steps of an execution from `state` contribute, in order. -/
def collect {α : Type} (config : Config) (observe : Pair.State → Pair.Action → List α)
    : Pair.State → List Pair.Action → List α
  | _, [] => []
  | state, action :: rest =>
      observe state action
      ++ match Pair.step config state action with
          | some next => collect config observe next rest
          | none => []

/-- All the plaintext accepted from the owner at `side` along an execution. -/
def acceptedAlong (config : Config) (side : Pair.Side) (state : Pair.State)
    (actions : List Pair.Action)
    : List Payload :=
  collect config (accepted config · side) state actions

/-- All the plaintext handed to the owner at `side` along an execution. -/
def deliveredAlong (config : Config) (side : Pair.Side) (state : Pair.State)
    (actions : List Pair.Action)
    : List Payload :=
  collect config (delivered config · side) state actions

/-- Something is on its way to `side`: output queued at its peer, records in the socket
buffer it reads, or input it has buffered. -/
def InTransit (state : Pair.State) (side : Pair.Side) : Prop :=
  (state.conn side.peer).output ≠ []
  ∨ (state.socket side).inbound ≠ []
  ∨ (state.conn side).ssl.input ≠ []

end Tls.Properties
