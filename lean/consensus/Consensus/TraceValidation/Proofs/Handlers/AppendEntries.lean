module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.TraceValidation.Proofs.Handlers.AeAgree
public import Consensus.TraceValidation.Proofs.Handlers.AeMatch

@[expose] public section

/-!
# Obligation: `recv_append_entries` (not reviewed)

`hoare_recv` (AeRecv) lists the ends of the hold from the released state; each is matched by
the clean receive of the request alone, whose ends `handle_nack`, `handle_silent` and
`handle_accept` (AeAgree) are taken after the term phase:

- a stale request is refused in the node's view, as by the clean model, which leaves the
  state unchanged;
- past the term phase (`aeMid`, clean `cleanMid`), a request whose previous term does not
  match is refused with cft.h's `find_highest_possible_match`, the clean
  `findHighestPossibleMatch` under `inv` (`highestMatch_eq`);
- a matching request before the commit index, or whose first conflict may not be rolled
  back, only records the leader;
- otherwise the node truncates at the first conflict, appends, commits and answers; the end
  state agrees with the clean `handleAppendEntiresFromPrimary` on the cut state
  (`accept_agrees`).

The conflict index the program scans for is the clean `firstTermConflictIndex`
(`ae_conflict`), and `msgInv` of the request gives the entry terms and the round trip of its
entries through the declared ledger (`ae_msg`).
-/

namespace Consensus.TraceValidation.Proofs

open CCF.Sections (LocalRun)
open Consensus.Model.Node
open Consensus.TraceValidation.Exec (State)
open Ae

theorem ae_rc {names : Names} {d : State} (h : inv names d = true)
    : forall x, x ∈ d.rcEntries -> d.commitIdx < x.1 := by
  have hc : d.rcEntries
      = (List.range' (d.commitIdx + 1) (d.lastIdx - d.commitIdx)).filterMap
          fun i => d.ledger[i - 1]?.bind
            fun e => if e.retired.isEmpty then none else some (i, e.retired) := by
    inv_conj h "rc_entries"
  intro x hx
  rw [hc, List.mem_filterMap] at hx
  obtain ⟨i, hi, he⟩ := hx
  rw [List.mem_range'_1] at hi
  cases hl : d.ledger[i - 1]? with
  | none => simp [hl] at he
  | some e =>
      simp only [hl, Option.bind_some] at he
      split at he
      · cases he
      · cases he; simp only; omega

theorem ae_conflict {names : Names} {d : State} (h : inv names d = true)
    (r : AppendEntriesRequest) (τ : Nat) (hτ : forall e, e ∈ r.entries -> e.term = τ)
    : ConflictSpec d r.prevLogIndex r.entries.length τ
        (firstTermConflictIndex (abs names d) r) := by
  have hs := ftci_spec (abs names d) r τ hτ
  obtain ⟨h1, -⟩ := inv_parts h
  have hlen := abs_log_length (names := names) h1
  have ht : forall j, 0 < j -> j <= d.lastIdx -> termAt (abs names d).log j = d.viewAt j := by
    intro j h0 hj
    rw [← getTerm_eq h]
    simp [State.getTerm]; omega
  rw [hlen] at hs
  cases hk : firstTermConflictIndex (abs names d) r with
  | none =>
      rw [hk] at hs
      intro j a b c
      rw [← ht j (by omega) b]; exact hs j a b c
  | some k =>
      rw [hk] at hs
      obtain ⟨a, b, c, e, f⟩ := hs
      refine ⟨a, b, c, ?_, fun j x y => ?_⟩
      · rw [← ht k (by omega) b]; exact e
      · rw [← ht j (by omega) (by omega)]; exact f j x y

theorem appendEntriesSound (env : Env) : AppendEntriesSound env := by
  intro node source r saved actions c vars others cleanOthers savedName savedId invSaved
    msgOk _ ran _ finished invVars
  simp only [plainFinish, Except.ok.injEq] at finished
  subst finished
  have request := msgOk source _ rfl
  have hsrc : env.names.id (env.names.name source) = source := msgInv_source request
  have hnode : env.names.id (env.names.name node) = node := by rw [← savedName]; exact savedId
  obtain ⟨hτe, hprev, hrt⟩ := ae_msg request
  obtain ⟨hsz, -, hcomm, -, -, hviews, -⟩ := inv_parts invSaved
  have hτ : forall j (h : j < ((r.entries.map (Exec.toExecEntry env)).toArray).size),
      ((r.entries.map (Exec.toExecEntry env)).toArray)[j].term = Exec.aeTermOfIdx r := by
    intro j h
    simp only [List.getElem_toArray, List.getElem_map]
    have := (hτe _ (List.getElem_mem (by simpa using h))).1
    rw [← this]
    unfold Exec.toExecEntry
    split <;> rfl
  have hv2 : Not (saved.currentView > r.term)
      -> (aeMid r saved).getTerm r.prevLogIndex = r.prevLogTerm
      -> Exec.aeTermOfIdx r <= r.term := by
    intro hns hm
    unfold Exec.aeTermOfIdx
    cases hl : r.entries.getLast? with
    | some e => exact (hτe e (List.mem_of_getLast? hl)).2.2
    | none =>
        simp only [Option.map_none, Option.getD_none]
        rw [← hm, aeMid_getTerm]
        have := viewAt_le_size' (v := saved) r.prevLogIndex
        simp only [State.getTerm]
        split <;> omega
  have hout := Hoare.run (hoare_recv (env := env) (env.names.name source) r
    (firstTermConflictIndex (abs env.names saved) r) saved hsz hcomm hviews (ae_rc invSaved) hτ
    (ae_conflict invSaved r _ fun e he => (hτe e he).1) hv2) ⟨rfl, rfl⟩ ran
  have hK := ae_conflict invSaved r _ fun e he => (hτe e he).1
  generalize hKdef : firstTermConflictIndex (abs env.names saved) r = K at hout hK
  have hUnid : (aeMid r saved).nodeId = saved.nodeId := (aeMid_frame r saved).2.2.2.2.2.2.1
  have hnid : c.vars.nodeId = saved.nodeId := by
    rcases hout with ⟨-, hv, -⟩ | ⟨-, -, ⟨-, hv, -⟩ | ⟨-, ⟨-, hv, -⟩ | ⟨-, -, ⟨-, hv, -⟩
      | ⟨-, hg, -, -⟩⟩⟩⟩
    · rw [hv]
    · rw [hv]; exact hUnid
    · rw [hv]; exact hUnid
    · rw [hv]; exact hUnid
    · have := hg.1.nodeId
      simp only [core, aePar] at this
      rw [this]; exact hUnid
  refine ⟨hnid, fun clean _ agreed unmatched => ?_⟩
  have reply : forall m : Message, (forall q, m ≠ .appendEntriesRequest q)
      -> c.outbox = [⟨node, source, m⟩]
      -> forall envelope, envelope ∈ c.outbox -> msgInv env.names envelope = true := by
    intro m hm hout envelope member
    rw [hout, List.mem_singleton] at member
    subst member
    exact msgInv_reply hnode request hm
  have run := fun clean' (out : CCF.Outputs NodeID Message Notification) step =>
    LocalRun.cons (protocol := protocol env) (node := node) (state := clean) (middle := clean')
      (action := (protocol env).receive source (.appendEntriesRequest r)) (effects := out) step
      (LocalRun.nil _)
  have step := clean_ae node source clean r
  obtain ⟨hterm, hlog⟩ := agrees_term_log agreed
  have hlen : clean.log.length = saved.lastIdx := by rw [hlog, abs_log_length hsz]
  rcases hout with ⟨stale, hv, ho⟩ | ⟨hns, hnl, hrest⟩
  · have hu : updateTerm clean r.term = clean := updateTerm_of_ge (by omega)
    have hcm : cleanMid clean r = clean := by
      unfold cleanMid
      split
      · rename_i h; omega
      · rfl
    rw [hu, handle_nack node source clean r (Or.inl (by rw [hcm]; omega)), hcm] at step
    simp only [show r.term < clean.currentTerm by omega, true_or, ↓reduceIte] at step
    have hout : c.outbox = [⟨node, source, aerMsg clean.currentTerm clean.log.length false⟩] := by
      rw [ho]; simp [aerOut, aerMsg, savedId, hsrc, hterm, hlen]
    refine ⟨[], clean, ?_, ?_, unmatched, by simp, reply _ (by simp [aerMsg]) hout⟩
    · simpa [cleanActions, hout] using run _ _ step
    · rw [hv]; exact agreed
  · have hagm := cleanMid_agrees (r := r) agreed hns
    have hN := handle_nack node source (updateTerm clean r.term) r
    have hS := handle_silent node source (updateTerm clean r.term) r
    have hA := handle_accept node source (updateTerm clean r.term) r
    generalize hcmdef : cleanMid (updateTerm clean r.term) r = cm at hagm hN hS hA
    obtain ⟨hterm', hlog'⟩ := agrees_term_log hagm
    rw [abs_aeMid_log] at hlog'
    obtain ⟨hlI, -, -, hciU, -, -, -, -⟩ := aeMid_frame r saved
    have h1 : Not (r.term < cm.currentTerm) := by rw [hterm', aeMid_view r saved hns]; omega
    have hgt : forall i, (aeMid r saved).getTerm i = termAt cm.log i := by
      intro i; rw [aeMid_getTerm, getTerm_eq invSaved, hlog']
    have hcmlen : cm.log.length = saved.lastIdx := by rw [hlog', abs_log_length hsz]
    have hrole : cm.role ≠ .primary := by rw [agrees_role hagm]; exact absRole_ne_primary hnl
    have hcci : cm.commitIndex = saved.commitIdx := by rw [(agrees_rci hagm).2.1, hciU]
    rcases hrest with ⟨hmis, hv, ho⟩ | ⟨hmatch, hrest⟩
    · have h2 : Not (appendEntryMatchesLog cm r) := fun ⟨_, h⟩ => hmis (by rw [hgt]; exact h)
      rw [hN (Or.inr h2)] at step
      simp only [h1, false_or] at step
      rw [hv] at invVars
      have hout : c.outbox = [⟨node, source,
          if termAt cm.log r.prevLogIndex = 0 then
            aerMsg cm.currentTerm cm.log.length false
          else
            aerMsg (termAt cm.log (findHighestPossibleMatch cm.log r.prevLogIndex r.prevLogTerm))
              (findHighestPossibleMatch cm.log r.prevLogIndex r.prevLogTerm) false⟩] := by
        rw [ho]
        unfold nackOut
        rw [highestMatch_eq invVars, abs_aeMid_log, ← hlog', hgt, hgt]
        split <;> simp [aerOut, aerMsg, hUnid, savedId, hsrc, hterm', hcmlen, hlI]
      refine ⟨[], cm, ?_, ?_, unmatched_of_role hrole, by simp,
        reply _ (by split <;> simp [aerMsg]) hout⟩
      · simpa [cleanActions, hout] using run _ _ step
      · rw [hv]; exact hagm
    · have hP : r.prevLogIndex <= saved.lastIdx := by
        apply Classical.byContradiction
        intro hgt'
        have h0 : (aeMid r saved).getTerm r.prevLogIndex = 0 := by
          simp only [State.getTerm, hlI]; split
          · rfl
          · omega
        omega
      have h2 : appendEntryMatchesLog cm r := ⟨by omega, by rw [← hgt]; exact hmatch⟩
      have hkn := agrees_known (env.names.name source) hagm
      have hrole' : ({ cm with primaryKnown := true } : NodeState).role ≠ .primary := hrole
      have hK' : firstTermConflictIndex cm r = K := by
        rw [← hKdef]; unfold firstTermConflictIndex; rw [hlog']
      have hnfc : cm.isNewFollower = (aeMid r saved).isNewFollower := (agrees_rci hagm).2.2
      rcases hrest with ⟨hlt, hv, ho⟩ | ⟨hci, -, hrest⟩
      · rw [hS h1 h2 (Or.inl (by omega))] at step
        refine ⟨[], _, ?_, ?_, unmatched_of_role hrole', by simp, by simp [ho]⟩
        · simpa [cleanActions, ho] using run _ _ step
        · rw [hv]; exact hkn
      · rcases hrest with ⟨hsil, hv, ho⟩ | ⟨hnsil, hg, hbd, ho⟩
        · rw [hS h1 h2 (Or.inr ⟨by rw [hK']; exact hsil.1, by
            have := hsil.2; simp only [aeU] at this; simp [hnfc, this]⟩)] at step
          refine ⟨[], _, ?_, ?_, unmatched_of_role hrole', by simp, by simp [ho]⟩
          · simpa [cleanActions, ho] using run _ _ step
          · rw [hv]; exact hkn
        · have h3 : Not (r.prevLogIndex < cm.commitIndex
              \/ ((firstTermConflictIndex cm r).isSome /\ !cm.isNewFollower)) := by
            rw [hK', hnfc, hcci]
            intro h
            rcases h with h | ⟨ha, hb⟩
            · omega
            · exact hnsil ⟨ha, by simpa [aeU] using hb⟩
          rw [hA h1 h2 h3, hK'] at step
          have hKU : ConflictSpec (aeU (env.names.name source) r saved) r.prevLogIndex
              r.entries.length (Exec.aeTermOfIdx r) K :=
            conflictSpec_congr (aeMid_frame r saved).1 (aeMid_frame r saved).2.2.1 hK
          obtain ⟨hres, hag⟩ := accept_agrees env (env.names.name source) r saved c.vars K cm
            invSaved invVars hkn hns hP hci hKU hrt hg hbd
          rw [savedId] at hres hag
          have hout : c.outbox = [⟨node, source,
              .appendEntriesResponse (handleAppendEntiresFromPrimary node (cutClean cm K) r).2⟩] := by
            rw [ho, hres]; simp [ack, hnid, savedId, hsrc]
          refine ⟨[], _, ?_, hag, unmatched_of_role ?_, by simp, reply _ (by simp) hout⟩
          · simpa [cleanActions, hout] using run _ _ step
          · rw [agrees_role hag]; exact absRole_ne_primary hg.1.nl

end Consensus.TraceValidation.Proofs
