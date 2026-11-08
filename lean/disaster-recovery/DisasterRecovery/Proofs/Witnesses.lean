module

public import DisasterRecovery.Properties.Utils

import all Init.Control.State

@[expose] public section

namespace DisasterRecovery.Proofs.Evaluation

open CCF
open Model.Local

/-- `List.merge` by structural recursion on fuel, so the kernel can evaluate it. -/
private def mergeFuel {α : Type} (le : α -> α -> Bool) : Nat -> List α -> List α -> List α
  | 0, xs, ys => xs ++ ys
  | _ + 1, [], ys => ys
  | _ + 1, x :: xs, [] => x :: xs
  | fuel + 1, x :: xs, y :: ys =>
      if le x y then
        x :: mergeFuel le fuel xs (y :: ys)
      else
        y :: mergeFuel le fuel (x :: xs) ys

private theorem merge_eq_mergeFuel {α : Type} (le : α -> α -> Bool)
    : forall (fuel : Nat) (xs ys : List α),
        xs.length + ys.length <= fuel -> List.merge xs ys le = mergeFuel le fuel xs ys
  | 0, [], [], _ => by simp [mergeFuel]
  | 0, _ :: _, _, h | 0, [], _ :: _, h => by simp at h
  | _ + 1, [], _, _ => by simp [mergeFuel]
  | _ + 1, _ :: _, [], _ => by simp [mergeFuel]
  | fuel + 1, x :: xs, y :: ys, h => by
      rw [List.cons_merge_cons, mergeFuel]
      split
      · rw [merge_eq_mergeFuel le fuel xs (y :: ys) (by simp at h ⊢; omega)]
      · rw [merge_eq_mergeFuel le fuel (x :: xs) ys (by simp at h ⊢; omega)]

/-- `List.mergeSort` by structural recursion on fuel, so the kernel can evaluate it. -/
private def mergeSortFuel {α : Type} (le : α -> α -> Bool) : Nat -> List α -> List α
  | 0, xs => xs
  | fuel + 1, xs =>
      if xs.length < 2 then
        xs
      else
        mergeFuel le xs.length (mergeSortFuel le fuel (xs.take ((xs.length + 1) / 2)))
          (mergeSortFuel le fuel (xs.drop ((xs.length + 1) / 2)))

private theorem mergeSort_eq_mergeSortFuel {α : Type} (le : α -> α -> Bool)
    : forall (fuel : Nat) (xs : List α),
        xs.length <= fuel -> xs.mergeSort le = mergeSortFuel le fuel xs
  | 0, [], _ => by simp [mergeSortFuel]
  | 0, _ :: _, h => by simp at h
  | fuel + 1, xs, h => by
      rw [mergeSortFuel]
      split
      · match xs, ‹xs.length < 2› with
        | [], _ => simp
        | [_], _ => simp
      · conv => lhs; rw [← List.take_append_drop ((xs.length + 1) / 2) xs]
        rw [List.mergeSort_append _ _ (by simp; omega) (by simp; omega),
          merge_eq_mergeFuel le xs.length _ _ (by simp; omega),
          mergeSort_eq_mergeSortFuel le fuel (xs.take _) (by simp; omega),
          mergeSort_eq_mergeSortFuel le fuel (xs.drop _) (by simp; omega)]

private theorem insertGossip_eval (source : Location) (txid : TxID)
    (gossips : List (Location × TxID))
    : insertGossip source txid gossips
      = if gossips.any (fun entry => entry.1 == source) then
          gossips
        else
          mergeSortFuel (fun left right => decide (left.1 <= right.1))
            (gossips.length + 1) ((source, txid) :: gossips) := by
  unfold insertGossip
  rw [mergeSort_eq_mergeSortFuel _ (gossips.length + 1) _ (by simp)]

private theorem insertVote_eval (source : Location) (votes : List Location)
    : insertVote source votes
      = if votes.contains source then
          votes
        else
          mergeSortFuel (fun left right => decide (left <= right)) (votes.length + 1)
            (source :: votes) := by
  unfold insertVote
  rw [mergeSort_eq_mergeSortFuel _ (votes.length + 1) _ (by simp)]

/-- Each recorded action leads from the previous state to the state paired with it. -/
private def StepsFrom (system : TransitionSystem)
    : system.State -> List (system.Action × system.State) -> Prop
  | _, [] => True
  | before, (action, after) :: rest =>
      system.step before action = some after /\ StepsFrom system after rest

private theorem stepsFrom_getElem? {system : TransitionSystem}
    : forall (initial : system.State) (steps : List (system.Action × system.State)),
        StepsFrom system initial steps
        -> forall (n : Nat) (before : system.State) (action : system.Action),
            (initial :: steps.map Prod.snd)[n]? = some before
            -> (steps.map Prod.fst)[n]? = some action
            -> system.step before action = (steps.map Prod.snd)[n]?
  | _, [], _, _, _, _, _, chosen => by simp at chosen
  | _, (_, _) :: _, ⟨step, _⟩, 0, _, _, first, chosen => by
      simp only [List.map_cons, List.getElem?_cons_zero, Option.some.injEq] at first chosen ⊢
      subst first chosen
      exact step
  | _, (_, after) :: rest, ⟨_, valid⟩, n + 1, before, action, first, chosen => by
      simp only [List.map_cons, List.getElem?_cons_succ] at first chosen ⊢
      exact stepsFrom_getElem? after rest valid n before action first chosen

/-- The finite trace that starts at `initial` and records `steps`. -/
private def ofSteps {system : TransitionSystem} (initial : system.State)
    (steps : List (system.Action × system.State)) (initialized : system.init initial)
    (valid : StepsFrom system initial steps)
    : Execution.Trace system :=
  ⟨
    { init := initial, steps := CCF.Seq.ofList steps },
    initialized,
    by
      intro n before action first chosen
      simp only [CCF.Seq.map_get?, CCF.Seq.ofList_get?] at chosen ⊢
      rw [← List.getElem?_map] at chosen ⊢
      refine stepsFrom_getElem? initial steps valid n before action ?_ chosen
      cases n <;>
        simpa only [CCF.Seq.get?_cons_zero, CCF.Seq.get?_cons_succ,
          CCF.Seq.map_get?, CCF.Seq.ofList_get?, List.getElem?_cons_zero,
          List.getElem?_cons_succ, List.getElem?_map] using first
  ⟩

end DisasterRecovery.Proofs.Evaluation

namespace DisasterRecovery.Proofs.Witnesses

open CCF
open Model.Local
open DisasterRecovery.Proofs.Evaluation

private def initial (config : Model.Config) : Model.State :=
  { nodes := config.protocol.expectedLocations.map fun node => (node, initialNode node) }

private theorem initialized {config : Model.Config} (valid : config.Valid)
    : (Model.transitionSystem config).init (initial config) := by
  refine ⟨valid, ?_, ?_, rfl, ?_⟩
  · simp [initial, Function.comp_def]
  · simpa [initial, Function.comp_def] using valid.2.1
  · intro entry member
    obtain ⟨node, _, rfl⟩ := List.mem_map.mp member
    rfl

private def high : TxID := { view := 1, seqno := 10 }

private def gossip (source target : Location) (txid : TxID) : Model.Envelope :=
  { source, target, payload := .gossip txid }

private def vote : Model.Envelope := { source := "A", target := "A", payload := .vote }

private def quorumConfig : Model.Config :=
  {
    protocol := { instanceId := "quorum-witness", expectedLocations := ["A"] }
    recovered := [("A", high)]
  }

private def quorumSelected : NodeState :=
  { location := "A", phase := .voting, chosen := some "A", gossips := [("A", high)] }

private def quorumReady : Model.State :=
  { nodes := [("A", quorumSelected)] }

private def quorumVoteSent : Model.State :=
  { quorumReady with network := [vote, gossip "A" "A" high] }

private def quorumOpener : NodeState :=
  { quorumSelected with phase := .opening, openKind := some .quorum, votes := ["A"] }

private def quorumOpened : Model.State :=
  {
    nodes := [("A", quorumOpener)]
    network := [gossip "A" "A" high]
  }

private def quorumSteps : List (Model.Action × Model.State) :=
  [
    (.local "A" .retry, { initial quorumConfig with network := [gossip "A" "A" high] }),
    (.deliver (gossip "A" "A" high), quorumReady),
    (.local "A" .retry, quorumVoteSent),
    (.deliver vote, quorumOpened)
  ]

private def quorumTrace : Properties.GlobalTrace quorumConfig :=
  ofSteps
    (initial quorumConfig)
    quorumSteps
    (initialized (by unfold Model.Config.Valid; decide))
    (by
      simp only [StepsFrom, quorumSteps, Model.transitionSystem,
        MultiNodeTransitionSystem.lift, Model.protocol, step, insertGossip_eval,
        insertVote_eval, and_true]
      and_intros <;> rfl)

private def fullConfig : Model.Config :=
  {
    protocol :=
      {
        instanceId := "full-gossip-failover-witness", expectedLocations := ["A", "B", "C"]
      }
    recovered :=
      [("A", high), ("B", { view := 1, seqno := 8 }), ("C", { view := 1, seqno := 5 })]
  }

private def fullSelected (node : Location) : NodeState :=
  {
    location := node,
    phase := .voting,
    chosen := some "A",
    gossips := fullConfig.recovered
  }

private def fullGossiped : Model.State :=
  { nodes := [("A", fullSelected "A"), ("B", fullSelected "B"), ("C", fullSelected "C")] }

private def failoverOpener : NodeState :=
  {
    fullSelected "A" with
      phase := .opening
      timeoutState := .opening
      votes := ["A"]
      openKind := some .failover
  }

private def failoverOpened : Model.State :=
  {
    fullGossiped with
      nodes := [("A", failoverOpener), ("B", fullSelected "B"), ("C", fullSelected "C")]
      network := [gossip "A" "A" high, gossip "A" "B" high, gossip "A" "C" high]
  }

private def fullPending (a b c : Nat) : List Model.Envelope :=
  fullConfig.recovered.zipIdx.flatMap
    fun (entry, index) =>
      ([("A", a), ("B", b), ("C", c)].filter fun target => decide (target.2 <= index)).map
        fun target => gossip entry.1 target.1 entry.2

private def partialNode (node : Location) (count : Nat) : NodeState :=
  match count with
  | 3 => fullSelected node
  | _ => { location := node, gossips := fullConfig.recovered.take count }

private def partialGossip (a b c : Nat) : Model.State :=
  {
    nodes :=
      [("A", partialNode "A" a), ("B", partialNode "B" b), ("C", partialNode "C" c)]
    network := fullPending a b c
  }

private def fullVoteSent : Model.State :=
  { fullGossiped with network := vote :: failoverOpened.network }

private def fullVoted : Model.State :=
  {
    fullGossiped with
      nodes :=
        [
          ("A", { fullSelected "A" with votes := ["A"] }),
          ("B", fullSelected "B"),
          ("C", fullSelected "C")
        ]
      network := failoverOpened.network
  }

private def fullTimeout : Model.State :=
  {
    fullVoted with
      nodes :=
        [
          ("A", { fullSelected "A" with votes := ["A"], timeoutState := .voting }),
          ("B", fullSelected "B"),
          ("C", fullSelected "C")
        ]
  }

private def fullSteps : List (Model.Action × Model.State) :=
  [
    (
      .local "A" .retry,
      { initial fullConfig with network := (fullPending 0 0 0).take 3 }
    ),
    (
      .local "B" .retry,
      { initial fullConfig with network := (fullPending 0 0 0).take 6 }
    ),
    (.local "C" .retry, partialGossip 0 0 0),
    (.deliver (gossip "A" "A" high), partialGossip 1 0 0),
    (.deliver (gossip "B" "A" { view := 1, seqno := 8 }), partialGossip 2 0 0),
    (.deliver (gossip "C" "A" { view := 1, seqno := 5 }), partialGossip 3 0 0),
    (.deliver (gossip "A" "B" high), partialGossip 3 1 0),
    (.deliver (gossip "B" "B" { view := 1, seqno := 8 }), partialGossip 3 2 0),
    (.deliver (gossip "C" "B" { view := 1, seqno := 5 }), partialGossip 3 3 0),
    (.deliver (gossip "A" "C" high), partialGossip 3 3 1),
    (.deliver (gossip "B" "C" { view := 1, seqno := 8 }), partialGossip 3 3 2),
    (.deliver (gossip "C" "C" { view := 1, seqno := 5 }), fullGossiped),
    (.local "A" .retry, fullVoteSent),
    (.deliver vote, fullVoted),
    (.local "A" .timeout, fullTimeout),
    (.local "A" .timeout, failoverOpened)
  ]

private def fullTrace : Properties.GlobalTrace fullConfig :=
  ofSteps
    (initial fullConfig)
    fullSteps
    (initialized (by unfold Model.Config.Valid; decide))
    (by
      simp only [StepsFrom, fullSteps, Model.transitionSystem,
        MultiNodeTransitionSystem.lift, Model.protocol, step, insertGossip_eval,
        insertVote_eval, and_true]
      and_intros <;> rfl)

private def frozenGossip : Properties.LocalStep :=
  {
    node := "A"
    before := quorumSelected
    action := .receiveGossip "A" high .accepted
    after := quorumSelected
    effects := { notifications := [.rejected "gossip-frozen"] }
  }

private def rejectedGossip : Properties.LocalStep :=
  {
    node := "A"
    before := initialNode "A"
    action := .receiveGossip "A" high .rejected
    after := initialNode "A"
    effects := { notifications := [.rejected "quote-or-certificate"] }
  }

private def quorumTimeout : Properties.LocalStep :=
  {
    node := "A"
    before := { quorumSelected with votes := ["A"] }
    action := .timeout
    after := { quorumOpener with timeoutState := .voting }
    effects := { notifications := [.opening .quorum] }
  }

private def openingTimeout : Properties.LocalStep :=
  {
    node := "A"
    before := { quorumOpener with timeoutState := .opening }
    action := .timeout
    after := { quorumOpener with timeoutState := .opening, phase := .open }
    effects := { notifications := [.completed] }
  }

private theorem quorum_notified
    : Properties.Trace.NotificationAt quorumConfig quorumTrace 3 "A"
        (.opening .quorum) := by
  refine ⟨
    quorumVoteSent,
    quorumOpened,
    .deliver vote,
    quorumSelected,
    quorumOpener,
    { notifications := [.opening .quorum] },
    rfl,
    rfl,
    rfl,
    rfl,
    rfl,
    rfl,
    ?_,
    by simp
  ⟩
  simp only [Properties.Trace.event, Model.receive, Model.protocol, step, insertVote_eval]
  rfl

theorem quorum_opener_unique_witness
    : exists (config : Model.Config) (trace : Properties.GlobalTrace config) (step
                                                                              : Nat) (opener
                                                                                      : Model.Local.Location),
        Properties.Trace.NotificationAt config trace step opener (.opening .quorum) :=
  ⟨quorumConfig, quorumTrace, 3, "A", quorum_notified⟩

theorem quorum_open_preserves_commit_witness
    : exists
    (config : Model.Config) (trace : Properties.GlobalTrace config) (openedState
                                                                      : Model.State),
    exists (opener : Model.Local.Location) (openerState : Model.Local.NodeState),
      openedState ∈ trace
      /\ (opener, openerState) ∈ openedState.nodes
      /\ openerState.openKind = some .quorum
      /\ (forall voter,
            voter ∈ openerState.votes -> Properties.ReceivedOwnGossip trace voter) := by
  refine ⟨
    quorumConfig,
    quorumTrace,
    quorumOpened,
    "A",
    quorumOpener,
    CCF.Execution.Trace.stateAt_mem (n := 4) ?_,
    by simp [quorumOpened],
    rfl,
    ?_
  ⟩
  · rfl
  · intro voter member
    have same : voter = "A" := by simpa [quorumOpener] using member
    subst voter
    refine ⟨quorumReady, CCF.Execution.Trace.stateAt_mem (n := 2) ?_,
      quorumSelected, high, by simp [quorumReady], by simp [quorumSelected]⟩
    rfl

theorem full_gossip_preserves_commit_witness
    : exists
    (config : Model.Config) (trace : Properties.GlobalTrace config) (gossipedState openedState
                                                                      : Model.State),
    exists (opener : Model.Local.Location) (openerState : Model.Local.NodeState),
      gossipedState ∈ trace
      /\ (forall node nodeState,
            node ∈ config.protocol.expectedLocations
            -> (node, nodeState) ∈ gossipedState.nodes
            -> forall gossip, gossip ∈ nodeState.gossips <-> gossip ∈ config.recovered)
      /\ openedState ∈ trace
      /\ (opener, openerState) ∈ openedState.nodes
      /\ openerState.openKind = some .failover := by
  refine ⟨
    fullConfig,
    fullTrace,
    fullGossiped,
    failoverOpened,
    "A",
    failoverOpener,
    CCF.Execution.Trace.stateAt_mem (n := 12) ?_,
    ?_,
    CCF.Execution.Trace.stateAt_mem (n := 16) ?_,
    by simp [failoverOpened],
    rfl
  ⟩
  · rfl
  · intro node nodeState _ member entry
    simp only [fullGossiped, List.mem_cons, List.not_mem_nil, or_false, Prod.mk.injEq] at member
    rcases member with ⟨rfl, rfl⟩ | ⟨rfl, rfl⟩ | ⟨rfl, rfl⟩ <;> rfl
  · rfl

theorem gossip_freezes_after_choice_witness
    : exists (config : Model.Config),
    exists localStep : Properties.LocalStep,
    exists (source : Model.Local.Location) (txid : Model.Local.TxID),
      (Model.protocol config).ValidStep localStep
      /\ localStep.action = .receiveGossip source txid .accepted
      /\ localStep.before.chosen.isSome = true := by
  refine ⟨quorumConfig, frozenGossip, "A", high, ?_, rfl, rfl⟩
  rfl

theorem rejected_gossip_stutters_witness
    : exists (config : Model.Config),
    exists localStep : Properties.LocalStep,
    exists (source : Model.Local.Location) (txid : Model.Local.TxID),
      (Model.protocol config).ValidStep localStep
      /\ localStep.action = .receiveGossip source txid .rejected := by
  refine ⟨quorumConfig, rejectedGossip, "A", high, ?_, rfl⟩
  rfl

theorem quorum_advance_opens_witness
    : exists (config : Model.Config),
    exists localStep : Properties.LocalStep,
      (Model.protocol config).ValidStep localStep
      /\ (localStep.action = .timeout
          \/ exists source, localStep.action = .receiveVote source .accepted)
      /\ localStep.before.phase = .voting
      /\ localStep.before.votes.length >= Model.Local.voteQuorum config.protocol := by
  refine ⟨quorumConfig, quorumTimeout, ?_, Or.inl rfl, rfl, by decide⟩
  rfl

theorem aligned_opening_timeout_completes_witness
    : exists (config : Model.Config),
    exists localStep : Properties.LocalStep,
      (Model.protocol config).ValidStep localStep
      /\ localStep.action = .timeout
      /\ localStep.before.phase = .opening
      /\ localStep.before.timeoutState = .opening := by
  refine ⟨quorumConfig, openingTimeout, ?_, rfl, rfl, rfl⟩
  rfl

end DisasterRecovery.Proofs.Witnesses
