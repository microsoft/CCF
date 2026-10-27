module

public import CCFRaft.Properties.Liveness.Assumptions.StableState
public import CCFRaft.Proofs.Duel.Witness

@[expose] public section

/-!
# A one-node witness for the commit-liveness premises

The one-node policy run's replay of the signed fixture: node 0 appends request 10
and a signature at time zero, then stays primary and idles forever.
These facts hold for every timing bound, so the premises of
`Properties.commit_liveness` hold alongside any election timeout.
-/

namespace CCFRaft.Proofs.Liveness.MinimalWitness

open CCFRaft.Liveness
open CCFRaft.Proofs.LivenessWitness
open CCFRaft.Proofs.Duel.Witness
open Model.Node
open HasProtocol (proto)
open HasTime (time)
open CCF.MultiNodeTransitionSystem (nodeState)

variable (sample : Sample)

/-- Every step after the first append is idle. -/
theorem idle_after {index : Nat} {step : DuelStep} (late : 1 <= index)
    (stepped : (run {0} policy sample).stepAt index = some step)
    : step.action = .idle := by
  rw [run_stepAt, Option.some.injEq] at stepped
  subst step
  cases index with
  | zero => omega
  | succ index => simp [liftStep, fixtureStep]

/-- The appended request and signature carry no configuration. -/
theorem appended_unconfigured {index : Nat} {step : DuelStep} {node : NodeID}
    {entries : List EntryContent} {entry : EntryContent}
    (stepped : (run {0} policy sample).stepAt index = some step)
    (appended : step.action = .local node (.append entries))
    (member : entry ∈ entries)
    : entry.metadata.configuration = none := by
  rw [run_stepAt, Option.some.injEq] at stepped
  subst step
  cases index with
  | zero =>
      simp only [liftStep, fixtureStep, ite_true, Event.local.injEq] at appended
      obtain ⟨-, input⟩ := appended
      cases input
      simp only [requestEntries, ite_true, List.cons_append, List.nil_append,
        List.mem_cons, List.not_mem_nil, or_false] at member
      rcases member with rfl | rfl <;> rfl
  | succ index => simp [liftStep, fixtureStep] at appended

/-- There are no pending packets, so every nonnegative delay bound holds. -/
theorem bounded_delay {delay : Real} (nonneg : 0 <= delay)
    : Satisfies (run {0} policy sample) (boundedDelayModel delay) := by
  refine ⟨⟨nonneg, ?_⟩, ?_⟩
  · intro packet member
    change packet ∈ ([] : List Packet) at member
    cases member
  · intro index step stepped
    rw [run_stepAt, Option.some.injEq] at stepped
    subst step
    intro packet member
    change packet ∈ ([] : List Packet) at member
    cases member

/-- The first append signs at time zero, after which nothing is unsigned. -/
theorem signatures {interval : Real} (nonneg : 0 <= interval)
    : SignatureScheduling (run {0} policy sample) (some interval) := by
  intro leader index point found due
  rw [run_stateAt, Option.some.injEq] at found
  subst point
  obtain ⟨leaderLive, state, nodeFound, _, _, unsigned⟩ := due
  have leaderZero : leader = 0 := Finset.mem_singleton.mp leaderLive
  subst leader
  cases index with
  | zero =>
      refine ⟨0, lift (fixtureWorld true 0), le_rfl, run_stateAt sample 0,
        le_add_of_nonneg_right nonneg, Or.inr ?_⟩
      exact ⟨
        liftStep (fixtureStep true 0),
        run_stepAt sample 0,
        requestEntries true,
        rfl,
        show EntryContent.signature ∈ requestEntries true by decide
      ⟩
  | succ index =>
      change some (requestedNode true) = some state at nodeFound
      have same := Option.some.inj nodeFound
      subst state
      have covered :
          Not (maxCommittableIndex (requestedNode true).log < (requestedNode true).log.length
            \/ maxCommittableTerm (requestedNode true).log
              ≠ (requestedNode true).currentTerm) := by decide
      exact False.elim (covered unsigned)

/-- No step runs a quorum check. -/
theorem check_quorum (window : Real)
    : CheckQuorumScheduling (run {0} policy sample) window := by
  intro index step leader stepped check
  rw [run_stepAt, Option.some.injEq] at stepped
  subst step
  cases index <;> simp [liftStep, fixtureStep] at check

private theorem no_resets (index node : Nat)
    : Not (ElectionReset (liftStep (fixtureStep true index)) node) := by
  cases index <;> simp [ElectionReset, liftStep, fixtureStep]

private theorem cannot_start (index : Nat)
    : Not (canStartElection (fixtureNode true index) 0) := by
  cases index <;> simp only [fixtureNode] <;> decide +kernel

/-- No node resets, times out or is ever due to, whatever the draw interval. -/
theorem election_scheduling (minimum : Option Real)
    : ElectionScheduling (run {0} policy sample) minimum none := by
  refine ⟨⟨?_⟩, ?_, fun _ _ _ _ => trivial⟩
  · intro index step stepped node
    rw [run_stepAt, Option.some.injEq] at stepped
    subst step
    exact ⟨fun reset => False.elim (no_resets index node reset), fun _ => rfl,
      fun timeout => False.elim (no_timeouts true index node timeout)⟩
  · intro node index point found due
    rw [run_stateAt, Option.some.injEq] at found
    subst point
    obtain ⟨_, _, state, nodeFound, can⟩ := due
    by_cases zero : node = 0
    · subst node
      change some (fixtureNode true index) = some state at nodeFound
      have same := Option.some.inj nodeFound
      subst state
      exact False.elim (cannot_start index can)
    · change ([(0, fixtureNode true index)].find? fun entry => entry.1 == node).map
          Prod.snd = some state at nodeFound
      have different : (0 == node) = false := by
        rw [beq_eq_false_iff_ne]
        exact Ne.symm zero
      simp [List.find?, different] at nodeFound

/-- The request is in the primary's log from index one. -/
theorem requested : HasRequest (requestedNode true).log 10 := by
  refine ⟨{ term := Model.BOOTSTRAP_TERM, content := .transaction 10 {} }, ?_, {}, rfl⟩
  simp [requestedNode, requestEntries]

/-- The primary's only active member is itself. -/
theorem active_members : (requestedNode true).activeMembers = {0} := by
  decide +kernel

/-- The primary's log removes no member. -/
theorem never_removed : retirementIndexInLog 0 (requestedNode true).log = none := by
  decide +kernel

/-- `Properties.commit_liveness_witness`: the one-node run `Duel.Witness.run` from
index one. -/
theorem commit_liveness_witness
    : forall (bounds : Liveness.Bounds) (maxDelay : Real),
        0 <= bounds.signatureInterval
        -> 0 <= maxDelay
        -> exists (config : Finset NodeID) (nodes : List NodeID),
        exists
        (trace : CCF.Execution.Trace Liveness.DuelWorld Liveness.Event) (start : Nat),
        exists (leader : NodeID) (request : ReqID),
          -- Protocol actions follow Raft from its configured initial state.
          (Liveness.Satisfies trace (Liveness.protocolModel config nodes)
            -- Every configuration names only listed nodes: the initial one, and every
            -- one appended anywhere in the trace.
            /\ config ⊆ nodes.toFinset
            /\ (forall index step node entries entry members,
                  trace.stepAt index = some step
                  -> step.action = .local node (.append entries)
                  -> entry ∈ entries
                  -> entry.metadata.configuration = some members
                  -> members ⊆ nodes.toFinset)
            -- Time never decreases; only idle steps may advance it.
            /\ Liveness.Satisfies trace Liveness.timingModel
            -- Time grows without bound, excluding finite traces and infinite time stalls.
            /\ Liveness.TimeDiverges trace
            -- Actors may crash and not recover
            /\ Liveness.Satisfies trace Liveness.crashModel
            -- Track actual sends and consume each packet at most once, FIFO with loss.
            /\ Liveness.Satisfies trace (Liveness.deliveryModel config nodes)
            -- Nonnegative delay; no pending packet to a live target becomes overdue.
            /\ Liveness.Satisfies trace (Liveness.boundedDelayModel maxDelay)
            -- Each due peer send happens within the heartbeat bound, or ceases to be due.
            /\ Liveness.HeartbeatScheduling trace (some bounds.heartbeatInterval)
            -- Each due signature is appended within the signature bound, or ceases to be due.
            /\ Liveness.SignatureScheduling trace (some bounds.signatureInterval)
            -- A primary steps down on a quorum check only once some active configuration
            -- lacks a majority of itself and peers heard from within the election timeout.
            /\ Liveness.CheckQuorumScheduling trace bounds.electionTimeout
            -- Reset deadlines lie in [E/2, E] and change only on resets; no early firing.
            -- Overdue eligible nodes eventually time out
            -- or cease to be due. `none` adds no upper bound on scheduling delay.
            /\ Liveness.ElectionScheduling trace (some (bounds.electionTimeout / 2)) none
            -- Fix the starting snapshot; this does not assert future stability.
            /\ Liveness.StableState trace start bounds nodes leader request
            -- No crashes from `start` onward; this does not forbid voluntary step-downs.
            /\ (forall index step node,
                  start <= index
                  -> trace.stepAt index = some step
                  -> Not (step.action = .crash node))
            -- No pending packet may be discarded from `start` onward.
            /\ (forall index step packet,
                  start <= index
                  -> trace.stepAt index = some step
                  -> Not (step.action = .drop packet))
            -- No primary nominates a successor from `start` onward.
            /\ (forall index step node,
                  start <= index
                  -> trace.stepAt index = some step
                  -> Not (step.action = .local node .nominateSuccessor))
            -- No configuration change is appended from `start` onward.
            /\ (forall index step node entries entry,
                  start <= index
                  -> trace.stepAt index = some step
                  -> step.action = .local node (.append entries)
                  -> entry ∈ entries
                  -> entry.metadata.configuration = none)) := by
  intro bounds maxDelay signing delay
  let sample : Liveness.Sample := fun _ => 0
  obtain ⟨protocol, timing, crash, delivery⟩ :=
    Proofs.Duel.Witness.admissible_unfolded sample
  refine ⟨
    {0},
    [0],
    Liveness.run {0} Proofs.Duel.Witness.policy sample,
    1,
    0,
    10,
    protocol,
    subset_refl _,
    ?_,
    timing,
    Proofs.Duel.Witness.diverges sample,
    crash,
    delivery,
    Proofs.Liveness.MinimalWitness.bounded_delay sample delay,
    Proofs.Duel.Witness.heartbeats sample _,
    Proofs.Liveness.MinimalWitness.signatures sample signing,
    Proofs.Liveness.MinimalWitness.check_quorum sample _,
    Proofs.Liveness.MinimalWitness.election_scheduling sample _,
    ⟨
      Proofs.Duel.Witness.lift (Proofs.LivenessWitness.fixtureWorld true 1),
      Proofs.LivenessWitness.requestedNode true,
      Proofs.Duel.Witness.run_stateAt sample 1,
      rfl,
      Finset.mem_singleton_self 0,
      by decide +kernel,
      Proofs.Liveness.MinimalWitness.requested,
      by decide +kernel,
      ?_,
      ?_,
      ?_
    ⟩,
    ?_,
    ?_,
    ?_,
    ?_
  ⟩
  · intro index step node entries entry members stepped appended member configured
    rw [Proofs.Liveness.MinimalWitness.appended_unconfigured sample stepped appended member] at configured
    cases configured
  · intro node member
    rcases member with rfl | member
    · exact Proofs.Liveness.MinimalWitness.never_removed
    · rw [Proofs.Liveness.MinimalWitness.active_members, Finset.mem_singleton] at member
      subst node
      exact Proofs.Liveness.MinimalWitness.never_removed
  · intro packet member
    simp [Liveness.HasNetwork.pending, Proofs.Duel.Witness.lift,
      Proofs.LivenessWitness.fixtureWorld] at member
  · intro node member
    rw [List.mem_singleton.mp member]
    exact ⟨Proofs.LivenessWitness.requestedNode true, rfl, Finset.mem_singleton_self 0,
      rfl, rfl, Or.inl rfl, Or.inl rfl, Or.inl rfl⟩
  · intro index step node late stepped crashed
    rw [Proofs.Liveness.MinimalWitness.idle_after sample late stepped] at crashed
    cases crashed
  · intro index step packet late stepped dropped
    rw [Proofs.Liveness.MinimalWitness.idle_after sample late stepped] at dropped
    cases dropped
  · intro index step node late stepped nominated
    rw [Proofs.Liveness.MinimalWitness.idle_after sample late stepped] at nominated
    cases nominated
  · intro index step node entries entry _ stepped appended member
    exact Proofs.Liveness.MinimalWitness.appended_unconfigured sample stepped appended member

end CCFRaft.Proofs.Liveness.MinimalWitness
