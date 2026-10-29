module

public import CCFRaft.Properties.Liveness.Model

@[expose] public section

/-!
# Scheduling policies with drawn election timeouts

A run model in which the timer draws are a sample, and a scheduling policy
builds the run from them. The witness of `Properties.commit_liveness` is such a
run.

CCF's `restart_election_timeout` (`raft.h`) draws a fresh uniform offset at every
reset. Here a sample is one offset per participant reset, consumed in trace order
from index 0. CCF's `start_ticking` sets a full election timeout without a draw at
node start; that is out of scope, so the initial deadlines are the policy's. It also
matters mid-run: a node joining a configuration starts ticking in
`execute_append_entries_sync` (`raft.h`), after the draw in `recv_append_entries`,
so CCF gives it exactly `E` where the model draws.

A `Policy` chooses the next event and every other nondeterministic part of the next
world from the recorded prefix; `run` builds the recording, overwriting the deadline
of each participant reset with `time + sample j`. The policy sees earlier draws
only through the deadlines in the prefix, so the `j`-th draw is independent of the
prefix before the `j`-th reset by construction; no non-anticipation premise.
-/

namespace CCFRaft.Liveness

open Model.Node
open HasProtocol (proto)
open HasTime (time)
open HasLive (live)
open HasNetwork (pending)
open HasTimers (deadline)
open CCF.MultiNodeTransitionSystem (nodeState)
open CCF.Execution (Trace)

/-! ## Samples -/

/-- The offset drawn by the `j`-th participant reset. -/
abbrev Sample := Nat -> Real

/-! ## The concrete world and the policy -/

/-- `World` with each node's pending election deadline. -/
structure DuelWorld extends World Model.State where
  deadlines : NodeID -> Real

instance : HasProtocol DuelWorld Model.State where
  proto world := world.proto

instance : HasTime DuelWorld where
  time world := world.time

instance : HasLive DuelWorld where
  live world := world.live

instance : HasNetwork DuelWorld where
  pending world := world.pending
  issued world := world.issued

instance : HasTimers DuelWorld where
  deadline world := world.deadlines

/-- A recorded step of a policy run. -/
abbrev DuelStep := CCF.Execution.Step DuelWorld Liveness.Event

/-- A scheduler: the initial world, and from the steps so far and the current world
the next event and proposed next world (or `none` to stop). It never sees the
sample, only the deadlines earlier draws produced. -/
structure Policy where
  initial : DuelWorld
  next : List DuelStep -> DuelWorld -> Option (Liveness.Event × DuelWorld)

open Classical in
/-- The number of participant resets among `history`: the next draw's index. -/
noncomputable def drawIndex (participants : Finset NodeID) (history : List DuelStep)
    : Nat :=
  history.countP
    fun step => decide (exists node, node ∈ participants /\ ElectionReset step node)

open Classical in
/-- The proposed step, with each participant reset drawing the next offset. A step
resets at most its actor, and the deadline does not affect `ElectionReset`. -/
noncomputable def stamp (participants : Finset NodeID) (sample : Sample)
    (history : List DuelStep) (before : DuelWorld) (event : Liveness.Event)
    (proposed : DuelWorld)
    : DuelStep :=
  let raw : DuelStep := { before, action := event, after := proposed }
  {
    raw with
      after :=
        {
          proposed with
            deadlines :=
              fun node =>
                if node ∈ participants /\ ElectionReset raw node then
                  before.time + sample (drawIndex participants history)
                else
                  proposed.deadlines node
        }
  }

/-- One step of `run` from the steps so far and the current world: the stamped
step and the extended history, or `none` once the policy stops. -/
noncomputable def advance (participants : Finset NodeID) (policy : Policy)
    (sample : Sample) (state : List DuelStep × DuelWorld)
    : Option (DuelStep × (List DuelStep × DuelWorld)) :=
  (policy.next state.1 state.2).map
    fun choice =>
      let step := stamp participants sample state.1 state.2 choice.1 choice.2
      (step, (state.1 ++ [step], step.after))

/-- An advanced step starts at the current world, and the next world is its after-state. -/
theorem advance_some {participants : Finset NodeID} {policy : Policy} {sample : Sample}
    {state next : List DuelStep × DuelWorld} {step : DuelStep}
    (advanced : advance participants policy sample state = some (step, next))
    : step.before = state.2 /\ next.2 = step.after := by
  simp only [advance, Option.map_eq_some_iff, Prod.mk.injEq] at advanced
  obtain ⟨_, _, rfl, rfl⟩ := advanced
  exact ⟨rfl, rfl⟩

section Corec

variable {participants : Finset NodeID} {policy : Policy} {sample : Sample}

/-- The first advanced step starts at the current world. -/
theorem advance_first (state : List DuelStep × DuelWorld) (step : DuelStep)
    (found
      : (Stream'.Seq.corec (advance participants policy sample) state).get? 0 = some step)
    : step.before = state.2 := by
  cases advanced : advance participants policy sample state with
  | none =>
      rw [Stream'.Seq.corec_nil _ _ advanced, Stream'.Seq.get?_nil] at found
      cases found
  | some pair =>
      obtain ⟨first, next⟩ := pair
      rw [Stream'.Seq.corec_cons advanced, Stream'.Seq.get?_cons_zero,
        Option.some.injEq] at found
      subst found
      exact (advance_some advanced).1

/-- Each advanced step starts where its predecessor ended. -/
theorem advance_linked (index : Nat)
    : forall (state : List DuelStep × DuelWorld) (previous following : DuelStep),
        (Stream'.Seq.corec (advance participants policy sample) state).get? index
          = some previous
        -> (Stream'.Seq.corec (advance participants policy sample) state).get? (index + 1)
            = some following
        -> previous.after = following.before := by
  induction index with
  | zero =>
      intro state previous following previousFound followingFound
      cases advanced : advance participants policy sample state with
      | none =>
          rw [Stream'.Seq.corec_nil _ _ advanced, Stream'.Seq.get?_nil] at previousFound
          cases previousFound
      | some pair =>
          obtain ⟨first, next⟩ := pair
          rw [Stream'.Seq.corec_cons advanced, Stream'.Seq.get?_cons_zero,
            Option.some.injEq] at previousFound
          rw [Stream'.Seq.corec_cons advanced, Stream'.Seq.get?_cons_succ] at followingFound
          subst previousFound
          rw [advance_first next following followingFound, (advance_some advanced).2]
  | succ index held =>
      intro state previous following previousFound followingFound
      cases advanced : advance participants policy sample state with
      | none =>
          rw [Stream'.Seq.corec_nil _ _ advanced, Stream'.Seq.get?_nil] at previousFound
          cases previousFound
      | some pair =>
          obtain ⟨first, next⟩ := pair
          rw [Stream'.Seq.corec_cons advanced, Stream'.Seq.get?_cons_succ]
            at previousFound followingFound
          exact held next previous following previousFound followingFound

end Corec

/-- The recording `policy` produces against `sample`. -/
noncomputable def run (participants : Finset NodeID) (policy : Policy) (sample : Sample)
    : Trace DuelWorld Liveness.Event where
  initial := policy.initial
  steps := Stream'.Seq.corec (advance participants policy sample) ([], policy.initial)
  first := advance_first ([], policy.initial)
  linked index := advance_linked index ([], policy.initial)

end CCFRaft.Liveness
