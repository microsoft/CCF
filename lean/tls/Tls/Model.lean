-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import CCF.TransitionSystem
public import Tls.Model.Engine

@[expose] public section

/-!
Two compositions of the engine model.

`node` is one node's engine: any number of connections, each facing an arbitrary peer, which
share only node-wide inbound admission. `pair` is two engines facing each other across the two
kernel socket buffers of one connection.
-/

namespace Tls.Model

/-- A fresh connection: established, with unused keys and nothing buffered. -/
def Conn.initial : Conn :=
  {}

namespace Node

/-- One of a node's connections, with its socket and whether its peer has closed. -/
structure Endpoint where
  /-- The engine's end. -/
  conn : Conn := .initial
  /-- The socket: `inbound` is what the peer has sent, `outbound` what it has yet to read. -/
  socket : Socket := {}
  /-- The peer has closed its end. -/
  peerClosed : Bool := false
deriving DecidableEq, Repr

/-- A node's connections and its inbound admission, which is all that they share. -/
structure State where
  /-- Node-wide inbound admission is saturated. -/
  saturated : Bool := false
  /-- The connections, in order of acceptance. -/
  endpoints : List Endpoint := []
deriving DecidableEq, Repr

/-- What can happen to one connection. The peer is unconstrained. -/
inductive Event where
  /-- A worker pass. -/
  | pass
  /-- The owner sends plaintext. -/
  | send (data : List Payload)
  /-- The engine closes the connection: shutdown, idle expiry, or a socket error. -/
  | abort
  /-- The peer writes any record. -/
  | peerSend (record : Record)
  /-- The peer reads one record. -/
  | peerReceive
  /-- The peer closes its end. -/
  | peerClose
deriving DecidableEq, Repr

/-- A node step. -/
inductive Action where
  /-- A connection is established. -/
  | accept
  /-- Inbound admission saturates or reopens. -/
  | admission (saturated : Bool)
  /-- An event on the connection at `index`. -/
  | connection (index : Nat) (event : Event)
deriving DecidableEq, Repr

/-- The pass a connection's worker would run, if one is due. -/
def Endpoint.pass (config : Config) (saturated : Bool) (endpoint : Endpoint)
    : Option Io :=
  Model.pass
    config
    { saturated, peerClosed := endpoint.peerClosed }
    { conn := endpoint.conn, socket := endpoint.socket }

/-- One event on one connection. Only a pass observes admission. -/
def Endpoint.step (config : Config) (saturated : Bool) (endpoint : Endpoint)
    : Event → Option Endpoint
  | .pass =>
      (endpoint.pass config saturated).map
        fun io =>
          { endpoint with conn := io.conn, socket := io.socket }
  | .send data =>
      (Model.send config data endpoint.conn).map fun conn => { endpoint with conn }
  | .abort =>
      if endpoint.conn.alive then
        some { endpoint with conn.alive := false }
      else
        none
  | .peerSend record =>
      if endpoint.peerClosed then
        none
      else
        some { endpoint with socket.inbound := endpoint.socket.inbound ++ [record] }
  | .peerReceive =>
      match endpoint.socket.outbound with
      | [] => none
      | _ :: rest => some { endpoint with socket.outbound := rest }
  | .peerClose =>
      if endpoint.peerClosed then
        none
      else
        some { endpoint with peerClosed := true }

/-- One node step. -/
def step (config : Config) (state : State) : Action → Option State
  | .accept => some { state with endpoints := state.endpoints ++ [{}] }
  | .admission saturated => some { state with saturated }
  | .connection index event => do
      let endpoint ← state.endpoints[index]?
      let next ← endpoint.step config state.saturated event
      pure { state with endpoints := state.endpoints.set index next }

end Node

/-- One node's engine, starting with no connections. -/
abbrev node (config : Config) : CCF.TransitionSystem where
  State := Node.State
  Action := Node.Action
  init state := state = {}
  step := Node.step config

namespace Pair

/-- The two ends of a connection. -/
inductive Side where
  /-- One end. -/
  | left
  /-- The other end. -/
  | right
deriving DecidableEq, Repr

/-- The other end. -/
def Side.peer : Side → Side
  | .left => .right
  | .right => .left

/-- Two engines, the socket buffer in each direction, and each node's inbound admission. -/
structure State where
  /-- The left engine's end. -/
  left : Conn := .initial
  /-- The right engine's end. -/
  right : Conn := .initial
  /-- Records written by the left engine which the right engine has not taken. -/
  toRight : List Record := []
  /-- Records written by the right engine which the left engine has not taken. -/
  toLeft : List Record := []
  /-- The left node's inbound admission is saturated. -/
  leftSaturated : Bool := false
  /-- The right node's inbound admission is saturated. -/
  rightSaturated : Bool := false
deriving DecidableEq, Repr

/-- A step of the two-engine system. -/
inductive Action where
  /-- A worker pass at one end. -/
  | pass (side : Side)
  /-- The owner at one end sends plaintext. -/
  | send (side : Side) (data : List Payload)
  /-- One end closes: shutdown, idle expiry, or a socket error. -/
  | abort (side : Side)
  /-- One node's inbound admission saturates or reopens. -/
  | admission (side : Side) (saturated : Bool)
deriving DecidableEq, Repr

/-- The engine at one end. -/
def State.conn (state : State) : Side → Conn
  | .left => state.left
  | .right => state.right

/-- Replace the engine at one end. -/
def State.setConn (state : State) (side : Side) (conn : Conn) : State :=
  match side with
  | .left => { state with left := conn }
  | .right => { state with right := conn }

/-- The socket as one end sees it: it reads what its peer wrote. -/
def State.socket (state : State) : Side → Socket
  | .left => { inbound := state.toLeft, outbound := state.toRight }
  | .right => { inbound := state.toRight, outbound := state.toLeft }

/-- Whether one end's node has saturated inbound admission. -/
def State.saturated (state : State) : Side → Bool
  | .left => state.leftSaturated
  | .right => state.rightSaturated

/-- The pass one end's worker would run, if one is due. -/
def State.pass (config : Config) (state : State) (side : Side) : Option Io :=
  Model.pass
    config
    { saturated := state.saturated side, peerClosed := !(state.conn side.peer).alive }
    { conn := state.conn side, socket := state.socket side }

/-- Store the result of a pass at one end. -/
def State.setIo (state : State) (side : Side) (io : Io) : State :=
  match side with
  | .left =>
      {
        state with
          left := io.conn, toLeft := io.socket.inbound, toRight := io.socket.outbound
      }
  | .right =>
      {
        state with
          right := io.conn, toRight := io.socket.inbound, toLeft := io.socket.outbound
      }

/-- One step of the two-engine system. -/
def step (config : Config) (state : State) : Action → Option State
  | .pass side => (state.pass config side).map (state.setIo side)
  | .send side data => (Model.send config data (state.conn side)).map (state.setConn side)
  | .abort side =>
      if (state.conn side).alive then
        some (state.setConn side { state.conn side with alive := false })
      else
        none
  | .admission .left saturated => some { state with leftSaturated := saturated }
  | .admission .right saturated => some { state with rightSaturated := saturated }

/-- The plaintext a step hands to the owner at `side`. -/
def deliveries (config : Config) (state : State) (side : Side) : Action → List Delivery
  | .pass actor =>
      if actor = side then ((state.pass config side).map (·.delivered)).getD [] else []
  | _ => []

end Pair

/-- Two engines on one connection, both established with nothing sent. -/
abbrev pair (config : Config) : CCF.TransitionSystem where
  State := Pair.State
  Action := Pair.Action
  init state := state = {}
  step := Pair.step config

end Tls.Model
