module

import all Init.Control.State
import all Init.Data.List.Sort.Basic
import all DisasterRecovery.TraceValidation

public import DisasterRecovery.Proofs.Lifting
public import DisasterRecovery.Tests.Initial

@[expose] public section

namespace DisasterRecovery.Tests.Activity

open CCF
open Model.Local

private def config : Model.Config :=
  {
    protocol := { instanceId := "activity-tests", expectedLocations := ["A", "B"] }
    recovered := [("A", { view := 1, seqno := 10 }), ("B", { view := 1, seqno := 5 })]
    active := ["A"]
  }

private def initial : Model.State :=
  {
    nodes :=
      [("unused", initialNode "unused"), ("B", initialNode "B"), ("A", initialNode "A")]
  }

private theorem initialized : (Model.transitionSystem config).init initial := by
  refine ⟨by unfold Model.Config.Valid; decide, ?_, by decide, rfl, ?_⟩
  · simp [initial, config]
  · simp [initial, Model.protocol]

private def gossip (target : Location) : Model.Envelope :=
  { source := "A", target, payload := .gossip { view := 1, seqno := 10 } }

private def sent : Model.State :=
  { initial with network := [gossip "A", gossip "B"] }

private theorem sentEnabled
    : (Model.transitionSystem config).step initial (.local "A" .retry) = some sent :=
  rfl

example : (Model.transitionSystem config).Reachable sent :=
  .step (.initial initialized) sentEnabled

example
    : exists decorated,
        Proofs.Execution.Global.Reachable config decorated
        /\ Proofs.Lifting.erase decorated = sent :=
  Proofs.Lifting.model_reachable_lifts (.step (.initial initialized) sentEnabled)

example : (Model.transitionSystem config).step initial (.local "B" .retry) = none := rfl

example : (Model.transitionSystem config).step initial (.local "B" .timeout) = none := rfl

example : (Model.transitionSystem config).step sent (.deliver (gossip "B")) = none := rfl

example : (Model.transitionSystem config).step initial (.local "unused" .retry) = none :=
  rfl

example
    : ((MultiNodeTransitionSystem.lift (Model.protocol config)).step sent
        (.deliver (gossip "B"))).isSome
      = false :=
  rfl

example
    : ((Model.protocol config).step (Capabilities.record "B") "B" (initialNode "B")
        .retry).run
        {}
      = none :=
  rfl

example : voteQuorum config.protocol = 2 := rfl

example
    : ¬ (Model.transitionSystem { config with active := ["unused"] }).init initial := by
  intro initialized
  have configured := initialized.1.2.2.2.2 "unused" (by simp)
  simp [config] at configured

example
    : ¬ (Model.transitionSystem config).init
          { initial with nodes := [("A", initialNode "A")] } := by
  intro initialized
  have covered := initialized.2.1 "B" (by simp [config])
  simp at covered

example
    : (TraceValidation.Header.make ["A", "B"] ["A"] config.recovered).initial
      = Tests.initial config :=
  rfl

end DisasterRecovery.Tests.Activity
