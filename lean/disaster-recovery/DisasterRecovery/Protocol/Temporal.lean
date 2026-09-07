import DisasterRecovery.Protocol.Model

/-! Human-reviewed local execution and fairness definitions. -/

namespace DisasterRecovery.Protocol

def EventuallyFrom (start : Nat) (predicate : Nat -> Prop) : Prop :=
  exists n, start <= n /\ predicate n

def AlwaysFrom (start : Nat) (predicate : Nat -> Prop) : Prop :=
  forall n, start <= n -> predicate n

def InfinitelyOften (predicate : Nat -> Prop) : Prop :=
  forall start, EventuallyFrom start predicate

def EventuallyAlways (predicate : Nat -> Prop) : Prop :=
  exists start, AlwaysFrom start predicate

structure Execution (config : Config) where
  states : Nat -> NodeState
  events : Nat -> Event
  step_succ : forall n,
    states (n + 1) = (step config (states n) (events n)).state

def WeakFairness
    {config : Config}
    (execution : Execution config)
    (enabled : NodeState -> Prop)
    (fired : NodeState -> Event -> Prop) : Prop :=
  forall start,
    AlwaysFrom start (fun n => enabled (execution.states n)) ->
    EventuallyFrom start
      (fun n => fired (execution.states n) (execution.events n))

def StrongFairness
    {config : Config}
    (execution : Execution config)
    (enabled : NodeState -> Prop)
    (fired : NodeState -> Event -> Prop) : Prop :=
  InfinitelyOften (fun n => enabled (execution.states n)) ->
  InfinitelyOften
    (fun n => fired (execution.states n) (execution.events n))

def AlignedOpening (state : NodeState) : Prop :=
  state.phase = .opening /\ state.timeoutState = .opening

end DisasterRecovery.Protocol
