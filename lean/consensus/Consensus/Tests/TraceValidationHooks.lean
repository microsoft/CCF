module

meta import Consensus.TraceValidation.Lockstep

public import Consensus.TraceValidation.Lockstep

public section

/-!
# M_tv: one entry carrying both configuration hooks

hooks.h's `ConfigurationChangeHook::call` can run, for one entry, the
`retired_committed_tx` hooks and then `add_configuration`. These checks run M_tv on a
synthetic hold of each kind, independently of the driver, and compare the release with
the clean model as `consensus-replay --refine` does.

Three nodes, view 2: `C1 = {n0, n1, n2}` at 1 and `C2 = {n0, n2}` at 3 are committed
(commit 4), so `n1`'s retirement is completed (and `n1` is still a peer). Entry 5 confirms `n1`'s retirement and
changes the configuration to `{n0}`. The same primary may not confirm `n2`, whose
retirement is not completed, nor add an empty configuration (second-kind guards).
-/

namespace Consensus.Tests.TraceValidationHooks

open Lean
open Consensus.Model.Node
open Consensus.TraceValidation
open Consensus.TraceValidation.Exec (State Action Ev)

private def check (condition : Bool) (message : String) : IO Unit :=
  unless condition do
    throw (IO.userError message)

private def names : Names := { known := #["n0", "n1", "n2"] }

private def env : Env :=
  {
    names,
    addrs := [("n0", "a0"), ("n1", "a1"), ("n2", "a2")],
    genesis := CCF.Finset.ofList [0]
  }

private def c1 : Exec.Nodes := [("n0", "a0"), ("n1", "a1"), ("n2", "a2")]
private def c2 : Exec.Nodes := [("n0", "a0"), ("n2", "a2")]
private def c3 : Exec.Nodes := [("n0", "a0")]

private def ledger : Array Exec.Entry :=
  #[
    { term := 2, sig := false, config := some c1 },
    { term := 2, sig := true },
    { term := 2, sig := false, config := some c2 },
    { term := 2, sig := true }
  ]

private def entry5 : Exec.Entry :=
  { term := 2, sig := false, config := some c3, retired := ["n1"] }

private def base : State :=
  {
    nodeId := "n0"
    currentView := 2
    lastIdx := 4
    commitIdx := 4
    views := #[1, 1]
    leaderId := some "n0"
    ticking := true
    configurations := [{ idx := 3, nodes := c2, rid := 3 }]
    ledger
  }

private def leader : State :=
  {
    base with
      leadership := .leader
      allOtherNodes :=
        [("n1", { sentIdx := 4, matchIdx := 4 }), ("n2", { sentIdx := 4, matchIdx := 4 })]
  }

private def follower : State :=
  {
    base with
      nodeId := "n2"
      leadership := .follower
      allOtherNodes :=
        [("n0", { sentIdx := 0, matchIdx := 0 }), ("n1", { sentIdx := 0, matchIdx := 0 })]
  }

private def nodesJson (ns : Exec.Nodes) : Json :=
  Json.mkObj (ns.map fun (id, addr) => (id, Json.mkObj [("address", toJson addr)]))

private def ev (node function : String) : Ev :=
  { file := "test", line := 0, process := "", hts := 0, node, function, msg := Json.null }

/-- Run one hold and check its release as `--refine` does. -/
private def hold (name : String) (saved : State) (recv : Option (NodeID × Message))
    (actions : List Action) (h : Exec.M Unit)
    : IO State := do
  let failed := (invChecks names saved).filter (!·.2) |>.map (·.1)
  check failed.isEmpty s!"{name}: saved state breaks {failed}"
  let ctx ←
    match Exec.run env saved actions true h with
    | .ok c => pure c
    | .error (.error e) => throw (IO.userError s!"{name}: M_tv rejects: {e}")
    | .error (.blocked _) => throw (IO.userError s!"{name}: M_tv blocked")
  check ctx.queue.isEmpty s!"{name}: actions left over"
  let node := names.id saved.nodeId
  let r : Release :=
    {
      node,
      ctx,
      vars := ctx.vars,
      sec := { head := ev saved.nodeId (actions.head!.point), recv, saved, actions, ctx }
    }
  match checkRelease env [(node, abs names saved)] r with
  | .ok (_, []) => pure ()
  | .ok (_, findings) => throw (IO.userError s!"{name}: {findings}")
  | .error e => throw (IO.userError s!"{name}: {e}")
  check (ctx.vars.ledger.back? == some entry5) s!"{name}: entry 5 is not {repr entry5}"
  return ctx.vars

private def primaryBothHooks : IO Unit := do
  let _ ←
    hold "primary" leader none
      [
        { point := "replicate", inputs := [] },
        {
          point := "replicate_entry", inputs := [("globally_committable", toJson false)]
        },
        { point := "retired_committed_tx", inputs := [("retired_node_id", toJson "n1")] },
        {
          point := "add_configuration",
          inputs := [("idx", toJson 5), ("nodes", nodesJson c3)]
        }
      ]
      Exec.replicate

private def followerBothHooks : IO Unit := do
  let request : AppendEntriesRequest :=
    {
      term := 2,
      prevLogIndex := 4,
      prevLogTerm := 2,
      entries := [absEntry names entry5],
      primaryCommit := 4
    }
  let _ ←
    hold "follower" follower (some (0, .appendEntriesRequest request))
      [
        { point := "recv_append_entries", inputs := [] },
        { point := "execute_append_entries_sync", inputs := [] },
        { point := "retired_committed_tx", inputs := [] },
        { point := "add_configuration", inputs := [] },
        { point := "send_append_entries_response", inputs := [] }
      ]
      (Exec.recvAppendEntries "n0" request)

/-- M_tv rejects the hold with a diagnostic naming `rule`. -/
private def rejects (name rule : String) (saved : State) (actions : List Action)
    (h : Exec.M Unit)
    : IO Unit :=
  match Exec.run env saved actions true h with
  | .error (.error e) =>
      check ((e.splitOn rule).length > 1) s!"{name}: rejected for another reason: {e}"
  | _ => throw (IO.userError s!"{name}: M_tv accepts")

/-- The second-kind admission guards on the primary. -/
private def primaryGuards : IO Unit := do
  let entry (hooks : List Action) : List Action :=
    [
      { point := "replicate", inputs := [] },
      { point := "replicate_entry", inputs := [("globally_committable", toJson false)] }
    ]
    ++ hooks
  rejects "confirm n2" "retirement confirmation" leader
    (entry
      [{ point := "retired_committed_tx", inputs := [("retired_node_id", toJson "n2")] }])
    Exec.replicate
  rejects "empty configuration" "empty configuration" leader
    (entry
      [{
        point := "add_configuration",
        inputs := [("idx", toJson 5), ("nodes", Json.mkObj [])]
      }])
    Exec.replicate

def run : IO Unit := do
  primaryBothHooks
  followerBothHooks
  primaryGuards
  IO.println "Trace validation hook checks passed."

#eval run

end Consensus.Tests.TraceValidationHooks
