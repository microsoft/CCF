module

public import CCFRaft.Proofs.Safety.Origin

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# Appends keep the primary's peers

Appending to a log whose commit index lies within it only adds active
configurations, so every eligible peer stays eligible. A configuration change
resets the retry index of, and sends requests to, newly added peers only.
-/

open CCF
open CCFRaft.Model.Node
open CCFRaft.Proofs.Safety

namespace CCFRaft.Proofs.Replication

theorem mem_configurationMembers_iff {configurations : List Configuration} {node : NodeID}
    : node ∈ configurationMembers configurations
      <-> exists configuration,
            configuration ∈ configurations /\ node ∈ configuration.nodes := by
  unfold configurationMembers
  suffices general
      : forall (acc : Finset NodeID) (configurations : List Configuration),
          node ∈ configurations.foldl (fun nodes next => nodes ∪ next.nodes) acc
          <-> node ∈ acc
            \/ exists configuration,
                configuration ∈ configurations /\ node ∈ configuration.nodes by
    simpa using general ∅ configurations
  intro acc configurations
  induction configurations generalizing acc with
  | nil => simp
  | cons head tail ih =>
      simp only [List.foldl_cons, ih, Finset.mem_union, List.mem_cons]
      grind

/-- Appending to a log only adds active configurations, while the commit index
lies within the log. -/
theorem activeConfigurations_append {log : List Entry} {commit : Nat}
    (frontier : commit <= log.length) (extra : List Entry)
    : exists rest,
        activeConfigurations (log ++ extra) commit
        = activeConfigurations log commit ++ rest := by
  obtain ⟨rest, split, later⟩ := configurationHistory_split (log ++ extra) log.length
  rw [List.take_left' rfl] at split
  refine ⟨rest, ?_⟩
  unfold activeConfigurations
  have bound := length_filter_le (configurationHistory log) commit
  simp only [split, filter_index_append frontier later]
  rw [List.drop_append_of_le_length (by omega)]

/-- Appending to a log keeps every eligible peer, while the commit index lies
within the log. -/
theorem eligiblePeers_append {before after : NodeState} (self : NodeID)
    (frontier : before.commitIndex <= before.log.length) {extra : List Entry}
    (logEq : after.log = before.log ++ extra)
    (commitEq : after.commitIndex = before.commitIndex)
    : eligiblePeers before self ⊆ eligiblePeers after self := by
  obtain ⟨rest, active⟩ := activeConfigurations_append frontier extra
  have members : before.activeMembers ⊆ after.activeMembers := by
    intro node member
    unfold NodeState.activeMembers NodeState.activeConfigurations at *
    rw [logEq, commitEq, active]
    obtain ⟨configuration, mem, inNodes⟩ := mem_configurationMembers_iff.mp member
    exact mem_configurationMembers_iff.mpr
      ⟨configuration, List.mem_append_left _ mem, inNodes⟩
  have retired : after.retirementCompletedNodes = before.retirementCompletedNodes := by
    unfold NodeState.retirementCompletedNodes NodeState.committedLog
    rw [logEq, commitEq, List.take_append_of_le_length frontier]
  unfold eligiblePeers
  rw [retired]
  exact Finset.erase_subset_erase _
    (Finset.union_subset_union members (Finset.Subset.refl _))

/-- A log's configuration history extends that of each of its prefixes by
configurations from later positions. -/
theorem configurationHistory_of_prefix {small large : List Entry} (sub : small <+: large)
    : exists rest,
        configurationHistory large = configurationHistory small ++ rest
        /\ forall configuration,
            configuration ∈ rest -> small.length < configuration.index := by
  obtain ⟨rest, split, later⟩ := configurationHistory_split large small.length
  rw [← List.prefix_iff_eq_take.mp sub] at split
  exact ⟨rest, split, later⟩

theorem filter_index_split {front rest : List Configuration} {bound : Nat}
    (inside : forall configuration, configuration ∈ front -> configuration.index <= bound)
    (later : forall configuration, configuration ∈ rest -> bound < configuration.index)
    : ((front ++ rest).filter fun configuration => configuration.index <= bound)
      = front := by
  rw [filter_index_append le_rfl later]
  exact List.filter_eq_self.mpr fun configuration member =>
    decide_eq_true (inside configuration member)

section Steps

variable (self : NodeID)

local notation "caps" => (Capabilities.record self : Caps)

/-- Appending an entry keeps the commit index, extends the log, leaves the retry
index of every eligible peer alone, and sends only to peers that were not
eligible. -/
theorem appendEntry_eligible (state : NodeState) (content : EntryContent)
    : Sends
        (fun next sent =>
          next.commitIndex = state.commitIndex
          /\ (exists extra, next.log = state.log ++ extra)
          /\ (forall peer,
                peer ∈ eligiblePeers state self
                -> next.sentIndex peer = state.sentIndex peer)
          /\ forall e, e ∈ sent -> Not (e.target ∈ eligiblePeers state self))
        (appendEntry caps self state content) := by
  unfold appendEntry
  simp only [pure_bind]
  repeat'
    first
    | refine Sends.ite' (fun _ => ?_) fun _ => ?_
    | refine Sends.guard_bind fun _ => ?_
  all_goals
    split
    · exact Sends.pure' ⟨rfl, ⟨_, rfl⟩, fun _ _ => rfl, by simp⟩
    · refine Sends.guard_bind fun _ => ?_
      refine Sends.guard_bind fun _ => ?_
      refine Sends.bind'
        (Sends.forIn' (R := fun e => Not (e.target ∈ eligiblePeers state self))
          fun peer _ member =>
            Sends.bind' (Sends.send _ _ _) fun _ _ eq => Sends.pure' fun e mem => ?_)
        fun _ _ done =>
          Sends.pure'
            ⟨rfl, ⟨_, rfl⟩, fun peer eligible => ?_, fun e mem => done e (by simpa using mem)⟩
      · subst eq
        simp only [List.append_nil, List.mem_singleton] at mem
        subst mem
        rw [Finset.mem_sort] at member
        exact (Finset.mem_sdiff.mp (Finset.mem_of_mem_erase member)).2
      · exact ite_eq_right fun added => (Finset.mem_sdiff.mp (Finset.mem_of_mem_erase added)).2 eligible

/-- A batch append leaves the retry index of every peer eligible before it alone,
and sends AppendEntries requests only to peers that were not eligible. -/
theorem appendBatch_eligible (before : NodeState) (contents : List EntryContent)
    (frontier : before.commitIndex <= before.log.length)
    : Sends
        (fun after sent =>
          (forall peer,
            peer ∈ eligiblePeers before self
            -> after.sentIndex peer = before.sentIndex peer)
          /\ forall e request,
              e ∈ sent
              -> e.payload = .appendEntriesRequest request
              -> Not (e.target ∈ eligiblePeers before self))
        (act caps self before (.append contents)) := by
  simp only [act]
  unfold appendBatch
  refine Sends.bind' Sends.guard' fun _ sent ⟨_, empty⟩ => ?_
  subst empty
  refine Sends.bind'
    (Sends.foldlM_mem
      (I :=
        fun (state : NodeState) (sent : List Model.Envelope) =>
          state.commitIndex = before.commitIndex
          /\ (exists extra, state.log = before.log ++ extra)
          /\ eligiblePeers before self ⊆ eligiblePeers state self
          /\ (forall peer,
                peer ∈ eligiblePeers before self
                -> state.sentIndex peer = before.sentIndex peer)
          /\ forall e, e ∈ sent -> Not (e.target ∈ eligiblePeers before self))
      contents
      (fun value _ item _ ⟨commitEq, ⟨extra, logEq⟩, grows, kept, held⟩ =>
        Sends.mono (appendEntry_eligible self value item)
          fun next later ⟨commitEq', ⟨extra', logEq'⟩, kept', fresh⟩ => by
            have valueFrontier : value.commitIndex <= value.log.length := by
              rw [commitEq, logEq, List.length_append]
              omega
            refine ⟨
              commitEq'.trans commitEq,
              ⟨
                extra ++ extra',
                by
                  rw [logEq', logEq, List.append_assoc]
              ⟩,
              grows.trans (eligiblePeers_append self valueFrontier logEq' commitEq'),
              fun peer eligible =>
                (kept' peer (grows eligible)).trans (kept peer eligible),
              fun e mem => ?_
            ⟩
            rcases List.mem_append.mp mem with old | new
            · exact held e old
            · exact fun eligible => fresh e new (grows eligible))
      before [] ⟨rfl, ⟨[], by simp⟩, Finset.Subset.refl _, fun _ _ => rfl, by simp⟩)
    fun appended sent ⟨_, _, _, kept, held⟩ => ?_
  refine Sends.mono (advanceCommit_sends self appended)
    fun after later ⟨advance, proposals⟩ =>
      ⟨fun peer eligible => ?_, fun e request mem => ?_⟩
  · rw [advance.sentIndex]
    exact kept peer eligible
  · intro payload
    have mem' : e ∈ sent \/ e ∈ later := by simpa using mem
    rcases mem' with old | new
    · exact held e old
    · rw [(proposals e new).2] at payload
      cases payload

end Steps

end CCFRaft.Proofs.Replication
