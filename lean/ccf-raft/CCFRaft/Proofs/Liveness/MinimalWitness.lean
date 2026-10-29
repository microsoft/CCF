module

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

end CCFRaft.Proofs.Liveness.MinimalWitness
