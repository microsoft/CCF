import DisasterRecovery.Protocol.Global

/-! Human-reviewed reachability and message-provenance invariants. -/

namespace DisasterRecovery.Protocol.Invariants

open Model hiding Config
open Global

structure HistoriesActive (state : State) : Prop where
  openings :
    forall opening, opening ∈ state.openings ->
      opening.node ∈ state.active
  restarts :
    forall node, node ∈ state.restarts ->
      node ∈ state.active
  completed :
    forall node, node ∈ state.completed ->
      node ∈ state.active

structure WellFormed (config : Config) (state : State) : Prop where
  nodeKeys :
    state.system.nodes.map Prod.fst =
      config.protocol.expectedLocations
  nodeKeysNodup : (state.system.nodes.map Prod.fst).Nodup
  nodeLocations :
    forall entry, entry ∈ state.system.nodes ->
      entry.2.location = entry.1
  activeNodup : state.active.Nodup
  activeConfigured :
    forall node, node ∈ state.active ->
      node ∈ config.protocol.expectedLocations
  sentValid :
    forall envelope, envelope ∈ state.sent ->
      envelope.Valid config
  sentSourceActive :
    forall envelope, envelope ∈ state.sent ->
      envelope.source ∈ state.active
  networkSent :
    forall envelope, envelope ∈ state.network ->
      envelope ∈ state.sent
  historiesActive : HistoriesActive state

end DisasterRecovery.Protocol.Invariants
