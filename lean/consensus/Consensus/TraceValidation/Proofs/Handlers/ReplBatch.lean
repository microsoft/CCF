module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.TraceValidation.Proofs.Handlers.ReplFlush
public import Consensus.TraceValidation.Proofs.Handlers.ReplPeerSend

@[expose] public section

/-!
# The clean batch alongside a hold (not reviewed; `Replicate` obligation)

`Ghost env node v0 cl0 es v o`: the clean entries `es`, appended and flushed as
`appendBatch` does, run from `cl0` and emit exactly the outbox `o`, into a clean state that
`Mid` relates to the declared state `v`. A range a flush sends extends the last entry's
flushes.
-/

namespace Consensus.TraceValidation.Proofs.Repl

open Consensus.Model.Node
open Consensus.TraceValidation.Exec
open Consensus.TraceValidation (Names abs agrees inv msgInv UnnamedUnmatched)

/-- One entry of `appendBatch`: append it, then send its flushes. -/
def entryStep (node : NodeID) (state : NodeState) (entry : AppendEntryInput)
    : NodeEffect NodeState := do
  let state <- appendEntry (CCF.Capabilities.record node) node state entry.content
  entry.flushes.foldlM
    (fun state (destination, endIndex) =>
      sendEntries (CCF.Capabilities.record node) node state destination endIndex)
    state

def Ghost (env : Env) (node : NodeID) (v0 : State) (cl0 : NodeState)
    (es : List AppendEntryInput) (v : State) (o : Outbox)
    : Prop :=
  exists cl,
    Emits (es.foldlM (entryStep node) cl0) cl o
    /\ Mid env.names node v0 cl0 cl v
    /\ forall x, x ∈ o -> msgInv env.names x = true

theorem foldl_flush (node : NodeID) (cl0 : NodeState) (es : List AppendEntryInput)
    (c : EntryContent) (fl : List (NodeID × Nat)) (x : NodeID × Nat)
    : (es ++ [({ content := c, flushes := fl ++ [x] } : AppendEntryInput)]).foldlM
        (entryStep node) cl0
      = (es ++ [({ content := c, flushes := fl } : AppendEntryInput)]).foldlM
          (entryStep node) cl0
        >>= fun s => sendEntries (CCF.Capabilities.record node) node s x.1 x.2 := by
  simp [List.foldlM_append, entryStep, bind_assoc]

variable {env : Env} {node : NodeID} {v0 : State} {cl0 : NodeState}

theorem Ghost.base {es : List AppendEntryInput} {v : State} {o : Outbox}
    (g : Ghost env node v0 cl0 es v o)
    : ViewHyps v
      /\ v.isRetiredCommitted = false
      /\ (v.allOtherNodes.map Prod.fst).Nodup := by
  obtain ⟨cl, -, M, -⟩ := g
  obtain ⟨f, -, P⟩ := M.clean
  exact ⟨M.vh, M.notRC, P.nodup⟩

theorem Ghost.bound {es : List AppendEntryInput} {v : State} {o : Outbox}
    (g : Ghost env node v0 cl0 es v o) {k : NodeId} {p : Peer}
    (found : v.peer? k = some p)
    : p.sentIdx <= v.lastIdx := by
  obtain ⟨cl, -, M, -⟩ := g
  obtain ⟨f, -, P⟩ := M.clean
  exact (P.rel k p found).2.1

/-- A range a flush sends extends the last entry's flushes. -/
theorem Ghost.flush (S : Start env.names node v0 cl0) {es : List AppendEntryInput}
    {c : EntryContent} {fl : List (NodeID × Nat)} {v : State} {o : Outbox}
    (g
      : Ghost env node v0 cl0
          (es ++ [({ content := c, flushes := fl } : AppendEntryInput)]) v o)
    {to : NodeId} {p : Peer} (found : v.peer? to = some p) {e : Nat} (ok : RangeOk v p e)
    : Ghost env node v0 cl0
        (es
          ++ [({ content := c, flushes := fl ++ [(env.names.id to, e)] }
              : AppendEntryInput)])
        (v.setPeer to { p with sentIdx := e }) (o ++ [rangeEnv env v to p e]) := by
  obtain ⟨cl, em, M, mi⟩ := g
  obtain ⟨em', M', mi'⟩ := range_step S M found ok.1 ok.2.1 ok.2.2
  have self := M.self S
  refine ⟨_, ?_, M', ?_⟩
  · rw [foldl_flush]
    refine emits_congr (emits_bind em em') rfl ?_
    simp only [rangeEnv, self]
  · intro x mem
    rcases List.mem_append.mp mem with mem | mem
    · exact mi x mem
    · simp only [List.mem_singleton] at mem
      subst mem
      simp only [rangeEnv, self]
      exact mi'

/-- A flush ghost: some entries, the last with some flushes. -/
def FlushGhost (env : Env) (node : NodeID) (v0 : State) (cl0 : NodeState) (v : State)
    (o : Outbox)
    : Prop :=
  exists es c fl,
    Ghost env node v0 cl0 (es ++ [({ content := c, flushes := fl } : AppendEntryInput)]) v
      o

open Consensus.TraceValidation.Proofs.Life in
/-- `send_append_entries` from a peer's send frontier during a flush keeps the flush ghost. -/
theorem flushSend_tri (S : Start env.names node v0 cl0) {to : NodeId} {ext : Bool}
    {start : Nat}
    : Tri env
        (fun v o =>
          FlushGhost env node v0 cl0 v o
          /\ exists p,
              v.peer? to = some p /\ start = p.sentIdx + 1 /\ p.sentIdx <= v.lastIdx)
        (sendAppendEntries to start ext) fun _ => FlushGhost env node v0 cl0 :=
  peerSend_tri (fun _ _ ⟨_, _, _, g⟩ => g.base)
    fun _ _ _ _ ⟨_, _, _, g⟩ found ok => ⟨_, _, _, g.flush S found ok⟩

end Consensus.TraceValidation.Proofs.Repl
