module

public import CCFRaft.Proofs.Replication.Peer

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# The stable primary's growing log

During stable leadership the primary only appends entries of its term. A node's
entry of that term lies inside the primary's log, so a fixed log keeps a fixed
agreement with the primary, and a peer of the term never loses agreement.
-/

open CCF.Execution (Trace)

namespace CCFRaft.Proofs.Timed

open CCF CCF.MultiNodeTransitionSystem
open CCFRaft.Liveness
open Model.Node
open HasProtocol (proto)
open CCFRaft.Proofs.Liveness (Admissible)
open CCFRaft.Proofs.Replication
open CCFRaft.Proofs.Safety
open CCFRaft.Proofs.StablePrimary
open CCFRaft.Proofs.CommitLiveness (stable_log_prefix)

/-- The window's agreed prefix is the agreement of the two logs. -/
theorem agreedPrefix_eq (leaderLog followerLog : List Entry)
    : agreedPrefix leaderLog followerLog = agree followerLog leaderLog := by
  induction leaderLog generalizing followerLog with
  | nil => cases followerLog <;> simp [agreedPrefix, agree]
  | cons x xs ih =>
      cases followerLog with
      | nil => simp [agreedPrefix, agree]
      | cons y ys =>
          have rest := ih ys
          simp only [agreedPrefix] at rest ⊢
          by_cases same : x = y
          · subst same
            simp [List.zip_cons_cons, agree, rest]
          · simp [List.zip_cons_cons, agree, same, Ne.symm same]

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]
  [Proofs.Config.InitialConfiguration] {nodes : List NodeID}
  {trace : Trace W Liveness.Event}
  (admissible : Admissible Proofs.Config.INITIAL_CONFIGURATION nodes trace)
  {start : Nat} {leader : NodeID} {term : Nat}
  (stable : StableLeader trace start leader term)

include admissible stable

/-- In one step the stable primary only appends entries of its term. -/
private theorem leader_step {index : Nat} (le : start <= index)
    {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step) {before after : NodeState}
    (beforeFound : nodeState (proto step.before) leader = some before)
    (afterFound : nodeState (proto step.after) leader = some after)
    : exists extension,
        after.log = before.log ++ extension
        /\ forall entry, entry ∈ extension -> entry.term = term := by
  have beforeAt : nodeAt trace index leader = some before := by
    rw [nodeAt_before stepped, beforeFound]
  have afterAt : nodeAt trace (index + 1) leader = some after := by
    rw [nodeAt_succ stepped, afterFound]
  cases selected : step.action.action with
  | none =>
      rw [admissible.stutter stepped selected, beforeFound, Option.some.injEq] at afterFound
      subst afterFound
      exact ⟨[], by simp, by simp⟩
  | some action =>
      obtain ⟨rest', c, _, _⟩ := ctx_at admissible stepped selected
      by_cases actorEq : c.tr.actor = leader
      swap
      · have kept :=
          found_of_now c.exec (c.now_other (Ne.symm actorEq) (now_of_found beforeFound))
        rw [afterFound, Option.some.injEq] at kept
        subst kept
        exact ⟨[], by simp, by simp⟩
      have prePre : c.tr.pre = before := by
        have found := c.tr.found
        rw [actorEq, beforeFound, Option.some.injEq] at found
        exact found.symm
      have postPost : c.tr.post = after := by
        have found := found_of_now c.exec c.post_now
        rw [show c.actor = leader from actorEq, afterFound, Option.some.injEq] at found
        exact found.symm
      have prePrimary : c.pre.role = .primary := by
        show c.tr.pre.role = .primary
        rw [prePre]
        exact stable.primary le beforeAt
      have preTerm : c.pre.currentTerm = term := by
        show c.tr.pre.currentTerm = term
        rw [prePre]
        exact stable.current le beforeAt
      have termEq : c.post.currentTerm = c.pre.currentTerm := by
        show c.tr.post.currentTerm = c.tr.pre.currentTerm
        rw [prePre, postPost, stable.current le beforeAt,
          stable.current (Nat.le_succ_of_le le) afterAt]
      have logEq {log : List Entry} (eq : c.post.log = c.pre.log ++ log)
          : after.log = before.log ++ log := by
        rw [← prePre, ← postPost]
        exact eq
      cases Summary.kind c.sum with
      | same log _ => exact ⟨[], logEq (by rw [log, List.append_nil]), by simp⟩
      | ack _ _ _ _ _ _ advance =>
          exact ⟨[], logEq (by rw [(Advance.facts advance).1, List.append_nil]), by simp⟩
      | append entries sent _ terms _ advance =>
          refine ⟨entries, logEq (Advance.facts advance).1, fun entry member => ?_⟩
          rw [terms entry member, preTerm]
      | elect wins =>
          exfalso
          obtain ⟨candidate, ⟨_, _, _, fresh | ⟨role, _⟩⟩, _, advance⟩ := wins
          · have postTerm := (Advance.facts advance).2.1
            have : (primaryState candidate).currentTerm = candidate.currentTerm := rfl
            have := fresh.2.1
            omega
          · rw [prePrimary] at role
            cases role
      | accept source request eq accepted =>
          exfalso
          obtain ⟨_, _, suffix, canon, aeok, _⟩ := c.accept_shape eq accepted
          have senderLed : Led (proto step.before :: rest') source request.term :=
            canon.2.2.2.mono suffix
          have actorLed := c.inv.leader_led c.actor c.pre c.pre_now prePrimary
          have termIs : request.term = c.pre.currentTerm := by
            rw [accepted.1, termEq]
          rw [termIs] at senderLed
          exact aeok.1 (c.inv.election_safety c.actor source _ actorLed senderLed)

/-- The stable primary only appends entries of its term. -/
theorem leader_grows {index later : Nat} (le : start <= index) (le' : index <= later)
    {old new : NodeState} (found : nodeAt trace index leader = some old)
    (found' : nodeAt trace later leader = some new)
    : exists extension,
        new.log = old.log ++ extension
        /\ forall entry, entry ∈ extension -> entry.term = term := by
  obtain ⟨last, lastFound, newFound⟩ := nodeAt_eq_some.mp found'
  refine trace.induction (start := index)
    (motive :=
      fun _ point =>
        forall new : NodeState,
          nodeState (proto point) leader = some new
          -> exists extension,
              new.log = old.log ++ extension
              /\ forall entry, entry ∈ extension -> entry.term = term)
    (fun point pointFound new nodeFound => ?_)
    (fun middle step began stepped ih new nodeFound => ?_) later last le' lastFound new
    newFound
  · rw [nodeAt_of_stateAt pointFound, nodeFound, Option.some.injEq] at found
    subst found
    exact ⟨[], by simp, by simp⟩
  · obtain ⟨_, middleState, middleFound, _⟩ :=
      stable.leads (le.trans began) (Trace.stateAt_of_stepAt stepped)
    obtain ⟨first, firstEq, firstTerms⟩ := ih middleState middleFound
    obtain ⟨second, secondEq, secondTerms⟩ :=
      leader_step admissible stable (le.trans began) stepped middleFound nodeFound
    refine ⟨first ++ second, by rw [secondEq, firstEq, List.append_assoc], ?_⟩
    intro entry member
    rcases List.mem_append.mp member with inFirst | inSecond
    · exact firstTerms entry inFirst
    · exact secondTerms entry inSecond

/-- A node's entry of the primary's term lies inside the primary's log, which
agrees with the node up to it. -/
theorem term_entry_within {index : Nat} (le : start <= index) {node : NodeID}
    {other primary : NodeState} (found : nodeAt trace index node = some other)
    (leaderFound : nodeAt trace index leader = some primary) {position : Nat}
    (positive : 0 < position) (bound : position <= other.log.length)
    (termEq : termAt other.log position = term)
    : position <= primary.log.length
      /\ other.log.take position = primary.log.take position := by
  obtain ⟨point, pointFound, leaderFound'⟩ := nodeAt_eq_some.mp leaderFound
  rw [nodeAt_of_stateAt pointFound] at found
  obtain ⟨rest, exec⟩ := history_at admissible pointFound
  have lead := lead_at stable le pointFound exec leaderFound'
  have now := now_of_found (rest := rest) found
  obtain ⟨log, canon, within, takeEq⟩ := lead.inv.anchor node other position now positive bound
  rw [termEq] at canon
  have sub := lead.canon canon
  exact ⟨within.trans sub.length_le, takeEq.trans (take_eq_of_prefix sub within).symm⟩

/-- A log recorded at a node keeps its agreement with the growing primary log. -/
theorem agree_stays {index later : Nat} (le : start <= index) (le' : index <= later)
    {node : NodeID} {other primary primary' : NodeState}
    (found : nodeAt trace index node = some other)
    (leaderFound : nodeAt trace index leader = some primary)
    (leaderFound' : nodeAt trace later leader = some primary')
    : agree other.log primary'.log = agree other.log primary.log := by
  obtain ⟨extension, extended, terms⟩ :=
    leader_grows admissible stable le le' leaderFound leaderFound'
  have grows : primary.log <+: primary'.log := by
    rw [extended]
    exact List.prefix_append _ _
  refine le_antisymm ?_ (agree_mono grows)
  by_contra more
  have more := Nat.lt_of_not_ge more
  have leftLe := agree_le_left other.log primary.log
  have rightLe := agree_le_right other.log primary.log
  have bigLeft := agree_le_left other.log primary'.log
  have bigRight := agree_le_right other.log primary'.log
  have bigTake := take_agree other.log primary'.log
  have nextTake
      : other.log.take (agree other.log primary.log + 1)
        = primary'.log.take (agree other.log primary.log + 1) := by
    have := congrArg (List.take (agree other.log primary.log + 1)) bigTake
    simpa [List.take_take, Nat.min_eq_left (show agree other.log primary.log + 1
      <= agree other.log primary'.log by omega)] using this
  by_cases inside : agree other.log primary.log + 1 <= primary.log.length
  · have := le_agree other.log primary.log (agree other.log primary.log + 1) (by omega) inside
      (nextTake.trans (take_eq_of_prefix grows inside))
    omega
  · have atEnd : agree other.log primary.log = primary.log.length := by omega
    have termNext
        : termAt other.log (agree other.log primary.log + 1) = term := by
      rw [← termAt_take (log := other.log) (le_refl _), nextTake,
        termAt_take (le_refl _), termAt_eq (by omega) (by omega)]
      apply terms
      have bound : agree other.log primary.log < primary'.log.length := by omega
      have get : primary'.log[agree other.log primary.log]'bound = extension[0]'(by
          have := congrArg List.length extended
          simp at this
          omega) := by
        simp only [extended, atEnd]
        simp
      simp only [Nat.add_sub_cancel]
      rw [get]
      exact List.getElem_mem _
    have := (term_entry_within admissible stable le found leaderFound (by omega) (by omega)
      termNext).1
    omega

variable {peer : NodeID} (different : Not (peer = leader))

include different

/-- A peer of the term never loses agreement with the primary in a step. -/
theorem agree_step {index : Nat} (le : start <= index)
    {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step) {pre post primary primary' : NodeState}
    (preFound : nodeState (proto step.before) peer = some pre)
    (postFound : nodeState (proto step.after) peer = some post)
    (preTerm : pre.currentTerm = term) (postTerm : post.currentTerm = term)
    (leaderFound : nodeState (proto step.before) leader = some primary)
    (leaderFound' : nodeState (proto step.after) leader = some primary')
    : agree pre.log primary.log <= agree post.log primary'.log := by
  have grows := stable_log_prefix admissible stable le (Nat.le_succ index)
    (by rw [nodeAt_before stepped, leaderFound])
    (by rw [nodeAt_succ stepped, leaderFound'])
  by_cases same : post.log = pre.log
  · rw [same]
    exact agree_mono grows
  obtain ⟨_, request, leaderState, _, _, _, _, _, leaderFound'', within, postLog, differ, _⟩ :=
    follower_step admissible stable le stepped different preFound postFound preTerm postTerm same
  rw [leaderFound, Option.some.injEq] at leaderFound''
  subst leaderFound''
  have postPrefix : post.log <+: primary'.log := by
    rw [postLog]
    exact (List.take_prefix _ _).trans grows
  rw [agree_of_prefix postPrefix, postLog, List.length_take, Nat.min_eq_left within]
  by_contra more
  have more := Nat.lt_of_not_ge more
  apply differ
  have := congrArg (List.take (request.prevLogIndex + request.entries.length))
    (take_agree pre.log primary.log)
  simpa [List.take_take, Nat.min_eq_left more.le] using this

/-- A peer that stays in the term never loses agreement with the primary. -/
theorem agree_grows {index later : Nat} (le : start <= index) (le' : index <= later)
    (current
      : forall middle point,
          index <= middle
          -> middle <= later
          -> trace.stateAt middle = some point
          -> exists state,
              nodeState (proto point) peer = some state /\ state.currentTerm = term)
    {other other' primary primary' : NodeState}
    (found : nodeAt trace index peer = some other)
    (found' : nodeAt trace later peer = some other')
    (leaderFound : nodeAt trace index leader = some primary)
    (leaderFound' : nodeAt trace later leader = some primary')
    : agree other.log primary.log <= agree other'.log primary'.log := by
  obtain ⟨last, lastFound, peerFound⟩ := nodeAt_eq_some.mp found'
  rw [nodeAt_of_stateAt lastFound] at leaderFound'
  refine trace.induction (start := index)
    (motive :=
      fun middle point =>
        middle <= later
        -> forall state primaryState : NodeState,
            nodeState (proto point) peer = some state
            -> nodeState (proto point) leader = some primaryState
            -> agree other.log primary.log <= agree state.log primaryState.log)
    (fun point pointFound _ state primaryState stateFound primaryFound => ?_)
    (fun middle step began stepped ih bounded state primaryState stateFound
        primaryFound =>
      ?_)
    later last le' lastFound le_rfl other' primary' peerFound leaderFound'
  · rw [nodeAt_of_stateAt pointFound, stateFound, Option.some.injEq] at found
    rw [nodeAt_of_stateAt pointFound, primaryFound, Option.some.injEq] at leaderFound
    subst found leaderFound
    exact le_rfl
  · obtain ⟨pre, preFound, preTerm⟩ :=
      current middle step.before began (by omega) (Trace.stateAt_of_stepAt stepped)
    obtain ⟨post, postFound, postTerm⟩ :=
      current (middle + 1) step.after (by omega) bounded (Trace.stateAt_succ_of_stepAt stepped)
    rw [stateFound, Option.some.injEq] at postFound
    subst postFound
    obtain ⟨_, middleState, middleFound, _⟩ :=
      stable.leads (le.trans began) (Trace.stateAt_of_stepAt stepped)
    exact (ih (by omega) pre middleState preFound middleFound).trans
      (agree_step admissible stable different (le.trans began) stepped preFound stateFound preTerm
        postTerm middleFound primaryFound)

end CCFRaft.Proofs.Timed
