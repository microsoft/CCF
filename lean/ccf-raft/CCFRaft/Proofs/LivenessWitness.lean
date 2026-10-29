module

public import CCFRaft.Proofs.Liveness
public import Mathlib.Tactic.NormNum

@[expose] public section

/-!
# A one-node liveness fixture

Node 0 appends request 10, with a signature if `signed`, then idles forever.
The fixture is valid for the protocol, timing, crash and delivery models; the
commit-liveness witness replays it.
-/

open CCF.Execution (Trace)

namespace CCFRaft.Proofs.LivenessWitness

open Model.Node
open CCFRaft.Liveness
open CCF.MultiNodeTransitionSystem (nodeState)

def initialNode : NodeState := Model.initialNodeState {0} 0

private def initialState : Model.State := { nodes := [(0, initialNode)] }

def requestEntries (signed : Bool) : List EntryContent :=
  [.transaction 10 {}] ++ if signed then [.signature] else []

def requestedNode (signed : Bool) : NodeState :=
  {
    initialNode with
      log :=
        initialNode.log
        ++ (requestEntries signed).map
            fun content => { term := Model.BOOTSTRAP_TERM, content }
      commitIndex := if signed then 3 else 0
  }

private def requestedState (signed : Bool) : Model.State :=
  { nodes := [(0, requestedNode signed)] }

def fixtureNode (signed : Bool) : Nat -> NodeState
  | 0 => initialNode
  | _ + 1 => requestedNode signed

def fixtureWorld (signed : Bool) (index : Nat) : World Model.State where
  proto := { nodes := [(0, fixtureNode signed index)] }
  time := ((index - 1 : Nat) : Real)
  live := {0}
  pending := []
  issued := 0

def fixtureStep (signed : Bool) (index : Nat)
    : CCF.Execution.Step (World Model.State) Liveness.Event where
  before := fixtureWorld signed index
  action := if index = 0 then .local 0 (.append (requestEntries signed)) else .idle
  after := fixtureWorld signed (index + 1)

/-- One append at time zero, which takes no time, followed by infinitely many idle
steps that each advance time by one.
There are no peers, hence no sends and no packet identities to advance. -/
def fixture (signed : Bool) : Trace (World Model.State) Liveness.Event where
  initial := fixtureWorld signed 0
  steps := Stream'.Seq.ofStream (fixtureStep signed)
  first _ found := by cases Option.some.inj found; rfl
  linked _ _ _ previous next := by
    cases Option.some.inj previous
    cases Option.some.inj next
    rfl

theorem fixture_stepAt (signed : Bool) (index : Nat)
    : (fixture signed).stepAt index = some (fixtureStep signed index) :=
  rfl

private theorem request_step (signed : Bool)
    : (Model.transitionSystem {0} [0]).step initialState
        (.local 0 (.append (requestEntries signed)))
      = some (requestedState signed) := by
  cases signed <;> rfl

private theorem request_outgoing (signed : Bool)
    : outgoing initialState (.local 0 (.append (requestEntries signed))) = some [] := by
  cases signed <;> rfl

theorem protocol_valid (signed : Bool)
    : Satisfies (fixture signed) (protocolModel {0} [0]) := by
  refine ⟨?_, ?_⟩
  · change (Model.transitionSystem {0} [0]).init initialState
    simp [initialState, Model.protocol, initialNode]
  · intro index step stepped
    rw [fixture_stepAt, Option.some.injEq] at stepped
    subst step
    cases index with
    | zero =>
        change (Model.transitionSystem {0} [0]).step initialState
          (.local 0 (.append (requestEntries signed))) = some (requestedState signed)
        exact request_step signed
    | succ index => rfl

theorem timing_valid (signed : Bool) : Satisfies (fixture signed) timingModel := by
  refine ⟨trivial, ?_⟩
  intro index step stepped
  rw [fixture_stepAt, Option.some.injEq] at stepped
  subst step
  cases index with
  | zero => exact ⟨le_rfl, fun _ => rfl⟩
  | succ index =>
      refine ⟨?_, fun busy => by simp [fixtureStep] at busy⟩
      change ((index + 1 - 1 : Nat) : Real) <= ((index + 1 + 1 - 1 : Nat) : Real)
      exact Nat.cast_le.mpr (by omega)

theorem crash_valid (signed : Bool) : Satisfies (fixture signed) crashModel := by
  refine ⟨trivial, ?_⟩
  intro index step stepped
  rw [fixture_stepAt, Option.some.injEq] at stepped
  subst step
  cases index <;> rfl

theorem delivery_valid (signed : Bool)
    : Satisfies (fixture signed) (deliveryModel {0} [0]) := by
  refine ⟨⟨rfl, rfl⟩, ?_⟩
  intro index step stepped
  rw [fixture_stepAt, Option.some.injEq] at stepped
  subst step
  cases index with
  | zero =>
      refine ⟨trivial, trivial, [], ?_, rfl, rfl⟩
      change (do
        let _ <- (Model.transitionSystem {0} [0]).step initialState
          (.local 0 (.append (requestEntries signed)))
        outgoing initialState (.local 0 (.append (requestEntries signed)))) = some []
      rw [request_step]
      exact request_outgoing signed
  | succ index => exact ⟨trivial, trivial, [], rfl, rfl, rfl⟩

theorem no_timeouts (signed : Bool) (index node : Nat)
    : Not ((fixtureStep signed index).action = .local node (.timeout .election)) := by
  cases index <;> simp [fixtureStep]

end CCFRaft.Proofs.LivenessWitness
