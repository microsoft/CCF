module

public import CCFRaft.Proofs.Liveness.Delay
public import CCFRaft.Proofs.Replication.Step
public import CCFRaft.Proofs.Leadership.Timers

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# Cutting a recording at a window's end

The timed argument runs the untimed replication lemmas, which assume a primary that
stays stable at every later recorded state, on a prefix of the recording that ends
inside the window. The prefix agrees with the recording on every state and step it
keeps, so it is admissible and recorded facts transfer back.
-/

open CCF.Execution (Trace)

namespace CCFRaft.Proofs.Timed

open CCF CCF.MultiNodeTransitionSystem
open CCFRaft.Liveness
open Model.Node
open HasProtocol (proto)
open HasTime (time)
open HasLive (live)
open HasNetwork (pending)
open CCFRaft.Proofs.Liveness (Admissible)

section Cut

variable {W A : Type}

/-- A step of the first `last` steps is a step of the recording. -/
theorem stepAt_of_take {trace : Trace W A} {last index : Nat}
    {step : CCF.Execution.Step W A}
    (found : (Stream'.Seq.ofList (trace.steps.take last)).get? index = some step)
    : index < last /\ trace.stepAt index = some step := by
  simp only [Stream'.Seq.ofList_get?, Stream'.Seq.getElem?_take] at found
  by_cases lt : index < last
  · simp only [lt, ↓reduceIte] at found
    exact ⟨lt, found⟩
  · simp [lt] at found

/-- The recording up to and including the state at `last`. -/
def cut (trace : Trace W A) (last : Nat) : Trace W A where
  initial := trace.initial
  steps := Stream'.Seq.ofList (trace.steps.take last)
  first step stepped := trace.first step (stepAt_of_take stepped).2
  linked index previous next previousAt nextAt :=
    trace.linked index previous next (stepAt_of_take previousAt).2
      (stepAt_of_take nextAt).2

theorem cut_stepAt (trace : Trace W A) (last index : Nat)
    : (cut trace last).stepAt index
      = if index < last then trace.stepAt index else none := by
  simp only [cut, Trace.stepAt, Stream'.Seq.ofList_get?, Stream'.Seq.getElem?_take]

theorem cut_stepAt_of_lt {trace : Trace W A} {last index : Nat} (lt : index < last)
    : (cut trace last).stepAt index = trace.stepAt index := by
  rw [cut_stepAt, ite_eq_left_iff.mpr fun no => absurd lt no]

theorem cut_stateAt_of_le {trace : Trace W A} {last index : Nat} (le : index <= last)
    : (cut trace last).stateAt index = trace.stateAt index := by
  cases index with
  | zero => rfl
  | succ index =>
      simp only [Trace.stateAt, cut_stepAt_of_lt (Nat.lt_of_succ_le le)]

theorem cut_stateAt_of_lt {trace : Trace W A} {last index : Nat} (lt : last < index)
    : (cut trace last).stateAt index = none := by
  cases index with
  | zero => omega
  | succ index =>
      have : Not (index < last) := by omega
      simp [Trace.stateAt, cut_stepAt, this]

/-- A step of the cut is a step of the recording. -/
theorem stepAt_of_cut {trace : Trace W A} {last index : Nat}
    {step : CCF.Execution.Step W A} (stepped : (cut trace last).stepAt index = some step)
    : index < last /\ trace.stepAt index = some step :=
  stepAt_of_take stepped

/-- A state of the cut is a state of the recording. -/
theorem stateAt_of_cut {trace : Trace W A} {last index : Nat} {point : W}
    (found : (cut trace last).stateAt index = some point)
    : index <= last /\ trace.stateAt index = some point := by
  by_cases le : index <= last
  · rw [cut_stateAt_of_le le] at found
    exact ⟨le, found⟩
  · rw [cut_stateAt_of_lt (Nat.lt_of_not_le le)] at found
    cases found

theorem Satisfies.cut {trace : Trace W A} {model : Model W A}
    (satisfies : Satisfies trace model) (last : Nat)
    : Satisfies (cut trace last) model :=
  ⟨
    satisfies.1,
    fun index step stepped => satisfies.2 index step (stepAt_of_cut stepped).2
  ⟩

end Cut

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]

theorem cut_nodeAt_of_le {trace : Trace W Liveness.Event} {last index : Nat}
    (le : index <= last) (node : NodeID)
    : nodeAt (cut trace last) index node = nodeAt trace index node := by
  simp only [nodeAt, cut_stateAt_of_le le]

theorem cut_sentAt {trace : Trace W Liveness.Event} {last index : Nat} (lt : index < last)
    {packet : Packet}
    : SentAt (cut trace last) index packet <-> SentAt trace index packet := by
  simp only [SentAt, cut_stepAt_of_lt lt]

theorem Admissible.cut {config : Finset NodeID} {nodes : List NodeID}
    {trace : Trace W Liveness.Event} (admissible : Admissible config nodes trace)
    (last : Nat)
    : Admissible config nodes (cut trace last) :=
  ⟨
    Satisfies.cut admissible.protocol last,
    Satisfies.cut admissible.timing last,
    Satisfies.cut admissible.crash last,
    Satisfies.cut admissible.delivery last
  ⟩

end CCFRaft.Proofs.Timed
