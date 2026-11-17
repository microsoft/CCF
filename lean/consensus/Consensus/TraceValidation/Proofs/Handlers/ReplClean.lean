module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.TraceValidation.Proofs.Handlers.ReplEmits
public import CCF.Proofs.Finset

@[expose] public section

/-!
# The clean `appendEntry` of an admissible entry

What the clean primary does for one admissible entry: the peers a configuration adds get
heartbeats from the end of the log and the entry is appended.
-/

namespace Consensus.TraceValidation.Proofs.Repl

open Consensus.Model.Node
open CCF (Finset)

/-- The peers a content's configuration adds: its nodes that are neither eligible nor the node. -/
def addedOf (cl : NodeState) (node : NodeID) (c : EntryContent) : Finset NodeID :=
  match c.metadata.configuration with
  | none => ∅
  | some nodes => (nodes \ eligiblePeers cl node).erase node

/-- The clean state after `appendEntry`. -/
def appended (node : NodeID) (cl : NodeState) (c : EntryContent) : NodeState :=
  {
    cl with
      sentIndex :=
        fun p => if p ∈ addedOf cl node c then cl.log.length else cl.sentIndex p
      log := cl.log ++ [{ term := cl.currentTerm, content := c }]
  }

/-- The heartbeat an added peer gets from the end of the log. -/
def hbClean (node : NodeID) (cl : NodeState) (p : NodeID) : CCF.Envelope NodeID Message :=
  ⟨
    node,
    p,
    .appendEntriesRequest
      {
        term := cl.currentTerm,
        prevLogIndex := cl.log.length
        prevLogTerm := termAt cl.log cl.log.length,
        entries := []
        primaryCommit := cl.commitIndex
      }
  ⟩

/-- `appendEntry`'s admission guards. -/
structure EntryOk (cl : NodeState) (c : EntryContent) : Prop where
  sig : c.isSignature = true -> Not (cl.log = [])
  rc
    : c.metadata.retirementConfirmations.Nonempty
      -> c.metadata.retirementConfirmations
          ⊆ cl.retirementCompletedNodes \ retiredCommittedNodes cl.log
  cfg
    : forall nodes,
        c.metadata.configuration = some nodes
        -> nodes.Nonempty
            /\ Not (nodes = latestConfigurationMembers (configurationHistory cl.log))
            /\ Finset.Disjoint nodes (removedNodes cl.log)

variable {node : NodeID}

theorem emits_appendEntry {cl : NodeState} {c : EntryContent} (ok : EntryOk cl c)
    : Emits (appendEntry (CCF.Capabilities.record node) node cl c) (appended node cl c)
        ((addedOf cl node c).sort.map (hbClean node cl)) := by
  unfold appendEntry
  dsimp only
  refine emits_ite_guard_bind ok.sig ?_
  refine emits_ite_guard_bind ok.rc ?_
  cases hc : c.metadata.configuration with
  | none =>
      refine emits_congr (emits_bind (emits_pure _) (emits_pure _)) ?_ ?_
      · simp only [appended, addedOf, hc, CCF.Finset.notMem_empty, ite_false]
      · simp only [addedOf, hc]
        rfl
  | some nodes =>
      dsimp only
      refine emits_congr (emits_bind (emits_guard (ok.cfg nodes hc))
        (emits_bind (emits_forIn_send _ _) (emits_pure _))) ?_ ?_
      · simp only [appended, addedOf, hc]
      · simp only [List.nil_append, List.append_nil, addedOf, hc]
        apply List.map_congr_left
        intro peer member
        simp only [CCF.Finset.mem_sort] at member
        simp only [hbClean, makeAppendEntriesRequest, member, ite_true, messageEntries,
          Nat.sub_self, List.take_zero]

end Consensus.TraceValidation.Proofs.Repl
