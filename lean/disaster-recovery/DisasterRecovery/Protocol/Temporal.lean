import DisasterRecovery.Protocol.Model

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

theorem valid_timeout_requires_alignment
    (state : NodeState)
    (h : validTimeout state true = true) :
    state.phase = state.timeoutState := by
  simpa [validTimeout] using h

theorem gossip_freezes_after_choice
    (config : Config)
    (state : NodeState)
    (source : Location)
    (txid : TxID)
    (h : state.chosen.isSome = true) :
    let output := step config state (.receiveGossip source txid .accepted)
    output.state = state /\ output.accepted = false := by
  cases chosen : state.chosen <;> simp_all [step, rejected]

theorem rejected_gossip_stutters
    (config : Config)
    (state : NodeState)
    (source : Location)
    (txid : TxID) :
    let output := step config state (.receiveGossip source txid .rejected)
    output.state = state /\ output.accepted = false := by
  simp [step, rejected]

theorem duplicate_vote_is_idempotent
    (source : Location)
    (votes : List Location)
    (h : votes.contains source = true) :
    insertVote source votes = votes := by
  unfold insertVote
  rw [h]
  simp

theorem opening_rejects_iamopen
    (config : Config)
    (state : NodeState)
    (source : Location) :
    let opening := { state with phase := .opening }
    let output := step config opening (.receiveIAmOpen source .accepted)
    output.state = opening /\ output.accepted = false := by
  simp [step, rejected]

theorem open_rejects_iamopen
    (config : Config)
    (state : NodeState)
    (source : Location) :
    let opened := { state with phase := .open }
    let output := step config opened (.receiveIAmOpen source .accepted)
    output.state = opened /\ output.accepted = false := by
  simp [step, rejected]

theorem aligned_voting_timeout_without_votes_stutters
    (config : Config)
    (state : NodeState) :
    let waiting := {
      state with
      phase := .voting
      timeoutState := .voting
      votes := []
    }
    step config waiting .timeout = { state := waiting } := by
  simp [step, advance, validTimeout, voteQuorum]

theorem aligned_opening_timeout_completes
    (config : Config)
    (state : NodeState) :
    let opening := {
      state with
      phase := .opening
      timeoutState := .opening
    }
    let output := step config opening .timeout
    output.state.phase = .open /\
      output.state.timeoutState = .opening /\
      output.effects = [.completed] := by
  simp [step, advance, validTimeout, advanceTimeoutLane, advanceTimeoutState]

theorem quorum_advance_opens
    (config : Config)
    (state : NodeState)
    (phase : state.phase = .voting)
    (quorum : state.votes.length >= voteQuorum config) :
    let output := (advance config state false).get!
    output.state.phase = .opening /\
      output.state.openKind = some .quorum /\
      output.effects = [.opening .quorum] := by
  simp [advance, phase, quorum, validTimeout, advanceTimeoutLane]

theorem aligned_empty_gossip_timeout_aborts
    (config : Config)
    (state : NodeState) :
    let waiting := {
      state with
      phase := .gossiping
      timeoutState := .gossiping
      gossips := []
    }
    let output := step config waiting .timeout
    output.state = waiting /\ output.accepted = false := by
  simp [step, advance, validTimeout, rejected, maximumGossip]

theorem non_timeout_step_preserves_aligned_opening
    (config : Config)
    (state : NodeState)
    (event : Event)
    (aligned : AlignedOpening state)
    (notTimeout : Not (event = .timeout)) :
    AlignedOpening (step config state event).state := by
  have phase := aligned.1
  have timeoutState := aligned.2
  cases event with
  | receiveGossip source txid validation =>
      cases validation <;>
        simp_all [AlignedOpening, step, rejected, advance, validTimeout,
          advanceTimeoutLane]
      split <;> simp_all
  | receiveVote source validation =>
      cases validation <;>
        simp_all [AlignedOpening, step, rejected, advance, validTimeout,
          advanceTimeoutLane]
  | receiveIAmOpen source validation =>
      cases validation <;>
        simp_all [AlignedOpening, step, rejected]
  | timeout =>
      exact (notTimeout rfl).elim
  | retry =>
      simp [AlignedOpening, step, phase, timeoutState]

theorem aligned_timeout_transitions_to_open
    (config : Config)
    (state : NodeState)
    (aligned : AlignedOpening state) :
    (step config state .timeout).state.phase = .open := by
  have phase := aligned.1
  have timeoutState := aligned.2
  simp [step, advance, validTimeout, phase, timeoutState,
    advanceTimeoutLane, advanceTimeoutState]

theorem fairness_supplies_firing
    {config : Config}
    (execution : Execution config)
    (enabled : NodeState -> Prop)
    (fired : NodeState -> Event -> Prop)
    (fair : WeakFairness execution enabled fired)
    (alwaysEnabled : forall n, enabled (execution.states n)) :
    InfinitelyOften
      (fun n => fired (execution.states n) (execution.events n)) := by
  intro start
  exact fair start (fun n _ => alwaysEnabled n)

theorem fair_aligned_opening_progress
    {config : Config}
    (execution : Execution config)
    (initial : AlignedOpening (execution.states 0))
    (fair : WeakFairness execution AlignedOpening
      (fun _ event => event = .timeout)) :
    EventuallyFrom 0
      (fun n => (execution.states n).phase = .open) := by
  apply Classical.byContradiction
  intro noOpen
  have neverOpen :
      forall n, Not ((execution.states n).phase = .open) := by
    intro n opened
    apply noOpen
    exact Exists.intro n (And.intro (Nat.zero_le n) opened)
  have alignedAlways : forall n, AlignedOpening (execution.states n) := by
    intro n
    induction n with
    | zero => exact initial
    | succ n aligned =>
        have notTimeout : Not (execution.events n = .timeout) := by
          intro timeout
          apply neverOpen (n + 1)
          rw [execution.step_succ n, timeout]
          exact aligned_timeout_transitions_to_open config _ aligned
        rw [execution.step_succ n]
        exact non_timeout_step_preserves_aligned_opening
          config _ _ aligned notTimeout
  have firing := fair 0 (fun n _ => alignedAlways n)
  let n := firing.choose
  have timeout := firing.choose_spec.2
  apply neverOpen (n + 1)
  rw [execution.step_succ n, timeout]
  exact aligned_timeout_transitions_to_open config _ (alignedAlways n)

end DisasterRecovery.Protocol