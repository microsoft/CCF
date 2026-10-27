module

public import CCFRaft.Properties.Liveness.Model.Policy
public import CCFRaft.Proofs.Config
public import Mathlib.Algebra.Order.Archimedean.Real.Basic
public import CCFRaft.Proofs.LivenessWitness

@[expose] public section

/-!
# A one-node policy run

The run behind `Properties.commit_liveness_witness`, built with `Liveness.run`.
It is constant in the sample: node 0 is primary throughout, so no participant reset consumes a draw.
The witness starts at index one, after the first append commits the bootstrap configuration.
-/

open CCF.Execution (Trace)

namespace CCFRaft.Proofs.Duel.Witness

open CCFRaft.Liveness
open CCFRaft.Proofs.LivenessWitness
open Model.Node
open HasProtocol (proto)
open HasTime (time)
open CCF.MultiNodeTransitionSystem (nodeState)

/-- The fixture's one-node initial configuration. -/
@[instance_reducible]
def initialConfiguration : Config.InitialConfiguration := ⟨{0}⟩

attribute [local instance] initialConfiguration

def nodes : List NodeID := [0]

/-- Add a constant zero election deadline to the fixture. -/
def lift (world : World Model.State) : DuelWorld where
  toWorld := world
  deadlines := fun _ => 0

def liftStep (step : CCF.Execution.Step (World Model.State) Liveness.Event)
    : DuelStep where
  before := lift step.before
  action := step.action
  after := lift step.after

/-- Replay the signed fixture, independently of any draws. -/
def policy : Policy where
  initial := lift (fixtureWorld true 0)
  next history _ :=
    some
      (
        (fixtureStep true history.length).action,
        lift (fixtureWorld true (history.length + 1))
      )

private theorem stamp_fixture (sample : Sample) (history : List DuelStep) (index : Nat)
    : stamp {0} sample history (lift (fixtureWorld true index))
        (fixtureStep true index).action (lift (fixtureWorld true (index + 1)))
      = liftStep (fixtureStep true index) := by
  cases index <;> simp [stamp, ElectionReset, fixtureStep, liftStep, lift]

private theorem advance_fixture (sample : Sample) (history : List DuelStep)
    : advance {0} policy sample (history, lift (fixtureWorld true history.length))
      = some
          (
            liftStep (fixtureStep true history.length),
            (
              history ++ [liftStep (fixtureStep true history.length)],
              lift (fixtureWorld true (history.length + 1))
            )
          ) := by
  simp only [advance, policy, Option.map_some, stamp_fixture]
  rfl

private theorem get?_fixture (sample : Sample) (history : List DuelStep) (index : Nat)
    : (Stream'.Seq.corec (advance {0} policy sample)
        (history, lift (fixtureWorld true history.length))).get?
        index
      = some (liftStep (fixtureStep true (history.length + index))) := by
  induction index generalizing history with
  | zero =>
      rw [Stream'.Seq.corec_cons (advance_fixture sample history)]
      simp
  | succ index ih =>
      rw [Stream'.Seq.corec_cons (advance_fixture sample history)]
      simpa [Nat.add_assoc, Nat.add_comm, Nat.add_left_comm]
        using ih (history ++ [liftStep (fixtureStep true history.length)])

/-- Every recorded step is the corresponding lifted fixture step. -/
theorem run_stepAt (sample : Sample) (index : Nat)
    : (run {0} policy sample).stepAt index
      = some (liftStep (fixtureStep true index)) := by
  change (Stream'.Seq.corec (advance {0} policy sample)
    ([], lift (fixtureWorld true 0))).get? index = _
  simpa using get?_fixture sample [] index

/-- Every recorded state is the corresponding lifted fixture state. -/
theorem run_stateAt (sample : Sample) (index : Nat)
    : (run {0} policy sample).stateAt index = some (lift (fixtureWorld true index)) := by
  cases index with
  | zero => rfl
  | succ index =>
      simp only [Trace.stateAt, run_stepAt, Option.map_some]
      rfl

/-- Lifting the fixture preserves all five admissibility obligations. -/
theorem admissible (sample : Sample)
    : CCFRaft.Proofs.Liveness.Admissible
        Config.INITIAL_CONFIGURATION nodes
        (run {0} policy sample) := by
  refine ⟨?_, ?_, ?_, ?_⟩
  · refine ⟨(protocol_valid true).1, ?_⟩
    intro index step stepped
    rw [run_stepAt, Option.some.injEq] at stepped
    subst step
    exact (protocol_valid true).2 index _ (fixture_stepAt true index)
  · refine ⟨(timing_valid true).1, ?_⟩
    intro index step stepped
    rw [run_stepAt, Option.some.injEq] at stepped
    subst step
    exact (timing_valid true).2 index _ (fixture_stepAt true index)
  · refine ⟨(crash_valid true).1, ?_⟩
    intro index step stepped
    rw [run_stepAt, Option.some.injEq] at stepped
    subst step
    exact (crash_valid true).2 index _ (fixture_stepAt true index)
  · refine ⟨(delivery_valid true).1, ?_⟩
    intro index step stepped
    rw [run_stepAt, Option.some.injEq] at stepped
    subst step
    exact (delivery_valid true).2 index _ (fixture_stepAt true index)

/-- Admissibility in the conjunction form used by `Properties`. -/
theorem admissible_unfolded (sample : Sample)
    : let trace := run {0} policy sample
      Satisfies trace (protocolModel Config.INITIAL_CONFIGURATION nodes)
      /\ Satisfies trace timingModel
      /\ Satisfies trace crashModel
      /\ Satisfies trace (deliveryModel Config.INITIAL_CONFIGURATION nodes) :=
  ⟨
    (admissible sample).protocol,
    (admissible sample).timing,
    (admissible sample).crash,
    (admissible sample).delivery
  ⟩

/-- Infinitely many idle steps advance the clock without bound. -/
theorem diverges (sample : Sample) : TimeDiverges (run {0} policy sample) := by
  intro bound
  obtain ⟨index, large⟩ := exists_nat_ge bound
  refine ⟨index + 1, lift (fixtureWorld true (index + 1)),
    run_stateAt sample (index + 1), ?_⟩
  change bound <= ((index + 1 - 1 : Nat) : Real)
  simpa using large

/-- With no replication peers, every heartbeat interval is sufficient. -/
theorem heartbeats (sample : Sample) (interval : Real)
    : HeartbeatScheduling (run {0} policy sample) (some interval) := by
  intro leader peer index point found due
  rw [run_stateAt, Option.some.injEq] at found
  subst point
  obtain ⟨leaderLive, peerLive, _, _, _, _, eligible⟩ := due
  have leaderZero : leader = 0 := Finset.mem_singleton.mp leaderLive
  have peerZero : peer = 0 := Finset.mem_singleton.mp peerLive
  subst leader peer
  simp [eligiblePeers] at eligible

end CCFRaft.Proofs.Duel.Witness
