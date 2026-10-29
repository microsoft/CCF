module

public import CCFRaft.Proofs.Replication.Commit

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# A settled configuration

While the stable primary has a single active configuration, that configuration
never changes, unless every configuration it ever has consists of the primary
alone. Appending a new configuration leaves it uncommitted beside the old one,
unless the primary alone already forms a majority of both.
-/

open CCF.Execution (Trace)

namespace CCFRaft.Proofs.Timed

open CCF CCF.MultiNodeTransitionSystem
open CCFRaft.Liveness
open Model.Node
open HasProtocol (proto)
open CCFRaft.Proofs.Liveness (Admissible)
open CCFRaft.Proofs.Safety
open CCFRaft.Proofs.Replication
open CCFRaft.Proofs.CommitLiveness (stable_log_prefix)

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]
  [Proofs.Config.InitialConfiguration] {nodes : List NodeID}
  {trace : Trace W Liveness.Event}
  (admissible : Admissible Proofs.Config.INITIAL_CONFIGURATION nodes trace)

theorem last_of_drop {l : List Configuration} {n : Nat} {configuration : Configuration}
    (eq : l.drop n = [configuration])
    : exists init, l = init ++ [configuration] :=
  ⟨l.take n, by rw [← eq, List.take_append_drop]⟩

theorem last_unique {init init' : List Configuration} {first second : Configuration}
    (eq : init ++ [first] = init' ++ [second])
    : first = second := by
  have := congrArg List.getLast? eq
  simpa using this

theorem last_mem_drop {init : List Configuration} {configuration : Configuration}
    {n : Nat} (nonempty : (init ++ [configuration]).drop n ≠ [])
    : configuration ∈ (init ++ [configuration]).drop n := by
  rw [List.drop_append] at nonempty ⊢
  rcases Nat.lt_or_ge init.length n with lt | ge
  · rw [List.drop_eq_nil_of_le (by omega : init.length <= n), List.nil_append] at nonempty ⊢
    exact absurd (List.drop_eq_nil_of_le (by simp; omega)) nonempty
  · simp [show n - init.length = 0 by omega]

theorem single_committed {log : List Entry} {commit : Nat} {configuration : Configuration}
    (active : activeConfigurations log commit = [configuration])
    (two : 2 <= (configurationHistory log).length)
    : configuration.index <= commit := by
  unfold activeConfigurations at active
  dsimp only at active
  have length := congrArg List.length active
  rw [List.length_drop, List.length_singleton] at length
  have bound := List.length_filter_le (fun configuration : Configuration =>
    decide (configuration.index <= commit)) (configurationHistory log)
  have all :
      (List.filter (fun configuration : Configuration => decide (configuration.index <= commit))
          (configurationHistory log)).length
        = (configurationHistory log).length := by
    omega
  have member : configuration ∈ configurationHistory log :=
    List.mem_of_mem_drop (active ▸ List.mem_singleton_self _)
  have := List.length_filter_eq_length_iff.mp all configuration member
  simpa using this

theorem active_last {log : List Entry} {commit : Nat} {configuration : Configuration}
    (active : activeConfigurations log commit = [configuration])
    : exists init, configurationHistory log = init ++ [configuration] :=
  last_of_drop active

include admissible

/-- One recorded step of the stable primary keeps its single active configuration,
unless both the old and the new one are the primary alone. -/
theorem single_step {start : Nat} {leader : NodeID} {term : Nat}
    (stable : StableLeader trace start leader term) {index : Nat} (le : start <= index)
    {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step) {before after : NodeState}
    (beforeFound : nodeState (proto step.before) leader = some before)
    (afterFound : nodeState (proto step.after) leader = some after)
    {old new : Configuration}
    (oldActive : before.activeConfigurations = [old])
    (newActive : after.activeConfigurations = [new])
    : new = old \/ (old.nodes = {leader} /\ new.nodes = {leader}) := by
  have beforeAt : nodeAt trace index leader = some before := by
    rw [nodeAt_before stepped, beforeFound]
  have afterAt : nodeAt trace (index + 1) leader = some after := by
    rw [nodeAt_succ stepped, afterFound]
  have frontier := commit_le_length admissible beforeAt
  obtain ⟨rest, historyEq, later⟩ :=
    configurationHistory_of_prefix
      (stable_log_prefix admissible stable le (Nat.le_succ index) beforeAt afterAt)
  obtain ⟨init, oldEq⟩ := active_last oldActive
  obtain ⟨init', newEq⟩ := active_last newActive
  rcases List.eq_nil_or_concat rest with restNil | ⟨restInit, last, restEq⟩
  · left
    rw [restNil, List.append_nil, oldEq, newEq] at historyEq
    exact last_unique historyEq
  right
  have two : 2 <= (configurationHistory after.log).length := by
    rw [historyEq, oldEq, restEq]
    simp
    omega
  rw [oldEq, restEq, List.concat_eq_append, ← List.append_assoc, newEq] at historyEq
  have newLast : new = last := last_unique historyEq
  have newLater : before.log.length < new.index :=
    later new (by rw [restEq, newLast]; simp)
  have oldIndex : old.index <= before.log.length :=
    configurationHistory_index_le _ (by rw [oldEq]; simp)
  have newCommitted : new.index <= after.commitIndex := single_committed newActive two
  have ahead : before.log.length < after.commitIndex := by omega
  cases selected : step.action.action with
  | none =>
      exfalso
      rw [admissible.stutter stepped selected, beforeFound, Option.some.injEq] at afterFound
      subst afterFound
      omega
  | some action =>
      obtain ⟨rest', c, _, _⟩ := ctx_at admissible stepped selected
      have actorEq : c.tr.actor = leader := by
        by_contra other
        have kept :=
          found_of_now c.exec (c.now_other (Ne.symm other) (now_of_found beforeFound))
        rw [afterFound, Option.some.injEq] at kept
        subst kept
        omega
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
      have termEq : c.post.currentTerm = c.pre.currentTerm := by
        show c.tr.post.currentTerm = c.tr.pre.currentTerm
        rw [prePre, postPost, stable.current le beforeAt,
          stable.current (Nat.le_succ_of_le le) afterAt]
      have beyond : c.pre.log.length < c.post.commitIndex := by
        show c.tr.pre.log.length < c.tr.post.commitIndex
        rw [prePre, postPost]
        exact ahead
      have frontier' : c.pre.commitIndex <= c.pre.log.length := by
        show c.tr.pre.commitIndex <= c.tr.pre.log.length
        rw [prePre]
        exact frontier
      cases Summary.kind c.sum with
      | same _ commit => omega
      | ack _ _ _ _ _ _ advance =>
          exfalso
          rcases advance with ⟨eq, _⟩ | ⟨_, _, _, _, _, _, lt, commitEq, _⟩
          · have : c.post.commitIndex = c.pre.commitIndex := by rw [eq]
            omega
          · have bound : c.post.commitIndex <= c.pre.log.length := by
              rw [commitEq]
              exact (highestCommittableIndex_spec _ _ (commitEq ▸ lt)).1
            omega
      | append entries sent _ _ _ advance =>
          rcases advance with ⟨eq, _⟩ | ⟨log, _, _, _, _, _, lt, commitEq, _⟩
          · exfalso
            have : c.post.commitIndex = c.pre.commitIndex := by rw [eq]
            omega
          let middle : NodeState :=
            { c.pre with log := c.pre.log ++ entries, sentIndex := sent }
          have spec := highestCommittableIndex_spec middle c.actor (commitEq ▸ lt)
          dsimp only at spec
          rw [← commitEq] at spec
          obtain ⟨_, _, _, quorum⟩ := spec
          have alone
              : forall configuration,
                  configuration ∈ middle.activeConfigurations
                  -> configuration.index <= c.post.commitIndex
                  -> configuration.nodes = {leader} := by
            intro configuration member indexLe
            have majority :=
              hasQuorum_majority quorum (List.mem_filter.mpr ⟨member, by simpa using indexLe⟩)
            by_contra notAlone
            obtain ⟨node, support, _, different⟩ := other_member majority notAlone
            rw [Finset.mem_filter] at support
            rcases support.2 with self | matched
            · exact different (self.trans actorEq)
            · have bound : c.pre.matchIndex node <= c.pre.log.length := by
                rcases Nat.eq_zero_or_pos (c.pre.matchIndex node) with zero | positive
                · omega
                · obtain ⟨_, _, _, bound, _⟩ :=
                    c.match_pre prePrimary (fun eq => different (eq.trans actorEq)) positive
                  exact bound
              have : middle.matchIndex node = c.pre.matchIndex node := rfl
              omega
          obtain ⟨extra, extendEq, _⟩ := activeConfigurations_extend frontier' entries
          have middleEq : middle.activeConfigurations = c.pre.activeConfigurations ++ extra :=
            extendEq
          have preActive : c.pre.activeConfigurations = [old] := by
            show c.tr.pre.activeConfigurations = [old]
            rw [prePre]
            exact oldActive
          have oldMember : old ∈ middle.activeConfigurations := by
            rw [middleEq, preActive]
            simp
          have historyMiddle : configurationHistory middle.log = init' ++ [new] := by
            rw [← log]
            show configurationHistory c.tr.post.log = init' ++ [new]
            rw [postPost, newEq]
          have newMember : new ∈ middle.activeConfigurations := by
            have shape
                : middle.activeConfigurations
                  = (configurationHistory middle.log).drop
                      (((configurationHistory middle.log).filter
                            fun configuration => configuration.index <= middle.commitIndex).length
                        - 1) :=
              rfl
            have oldMember' := oldMember
            rw [shape, historyMiddle] at oldMember' ⊢
            exact last_mem_drop (List.ne_nil_of_mem oldMember')
          have postCommit : c.post.commitIndex = after.commitIndex := by
            show c.tr.post.commitIndex = after.commitIndex
            rw [postPost]
          have preLength : c.pre.log.length = before.log.length := by
            show c.tr.pre.log.length = before.log.length
            rw [prePre]
          exact ⟨alone old oldMember (by omega), alone new newMember (by omega)⟩
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

/-- A property of the single active configuration that holds at `start` and survives
every step of the stable primary holds from `start` on. -/
theorem single_propagates {start : Nat} {leader : NodeID} {term : Nat}
    (stable : StableLeader trace start leader term)
    (single
      : forall index state,
          start <= index
          -> nodeAt trace index leader = some state
          -> state.activeConfigurations.length = 1)
    (holds : Configuration -> Prop)
    (base
      : forall state,
          nodeAt trace start leader = some state
          -> forall configuration,
              state.activeConfigurations = [configuration] -> holds configuration)
    (next
      : forall old new,
          holds old
          -> (new = old \/ (old.nodes = {leader} /\ new.nodes = {leader}))
          -> holds new)
    : forall index state configuration,
        start <= index
        -> nodeAt trace index leader = some state
        -> state.activeConfigurations = [configuration]
        -> holds configuration := by
  intro index state configuration le found active
  obtain ⟨point, pointFound, nodeFound⟩ := nodeAt_eq_some.mp found
  refine trace.induction (start := start)
    (motive :=
      fun _ point =>
        forall state,
          nodeState (proto point) leader = some state
          -> forall configuration,
              state.activeConfigurations = [configuration] -> holds configuration)
    (fun point found state nodeFound =>
      base state (by rw [nodeAt_of_stateAt found, nodeFound]))
    (fun index step le stepped held _ afterFound new newActive => ?_)
    index point le pointFound state nodeFound configuration active
  obtain ⟨_, before, beforeFound, _⟩ := stable.leads le (Trace.stateAt_of_stepAt stepped)
  obtain ⟨old, oldActive⟩ :=
    List.length_eq_one_iff.mp
      (single index before le (by rw [nodeAt_before stepped, beforeFound]))
  exact next old new (held before beforeFound old oldActive)
    (single_step admissible stable le stepped beforeFound afterFound oldActive newActive)

/-- A single active configuration at the stable primary is fixed, or every one is
the primary alone. -/
theorem configuration_fixed {start : Nat} {leader : NodeID} {term : Nat}
    (stable : StableLeader trace start leader term)
    (single
      : forall index state,
          start <= index
          -> nodeAt trace index leader = some state
          -> state.activeConfigurations.length = 1)
    : (exists configuration,
        forall index state,
          start <= index
          -> nodeAt trace index leader = some state
          -> state.activeConfigurations = [configuration])
      \/ (forall index state configuration,
            start <= index
            -> nodeAt trace index leader = some state
            -> configuration ∈ state.activeConfigurations
            -> configuration.nodes = {leader}) := by
  obtain ⟨point, pointFound⟩ := stable.1
  obtain ⟨initial, initialFound⟩ := stable.found le_rfl pointFound
  obtain ⟨base, baseActive⟩ :=
    List.length_eq_one_iff.mp (single start initial le_rfl initialFound)
  have baseOf
      : forall state,
          nodeAt trace start leader = some state
          -> forall configuration,
              state.activeConfigurations = [configuration] -> configuration = base := by
    intro state found configuration active
    rw [initialFound, Option.some.injEq] at found
    subst found
    rw [baseActive, List.cons.injEq] at active
    exact active.1.symm
  by_cases alone : base.nodes = {leader}
  · right
    have all :=
      single_propagates admissible stable single (fun configuration => configuration.nodes = {leader})
        (fun state found configuration active => by rw [baseOf state found configuration active]; exact alone)
        (fun _ _ held changed => by
          rcases changed with rfl | ⟨_, newAlone⟩
          · exact held
          · exact newAlone)
    intro index state configuration le found member
    obtain ⟨only, active⟩ := List.length_eq_one_iff.mp (single index state le found)
    rw [active, List.mem_singleton] at member
    subst member
    exact all index state _ le found active
  · left
    refine ⟨base, fun index state le found => ?_⟩
    have all :=
      single_propagates admissible stable single (fun configuration => configuration = base) baseOf
        (fun _ _ held changed => by
          rcases changed with eq | ⟨oldAlone, _⟩
          · exact eq.trans held
          · exact absurd (held ▸ oldAlone) alone)
    obtain ⟨only, active⟩ := List.length_eq_one_iff.mp (single index state le found)
    rw [active, all index state only le found active]

end CCFRaft.Proofs.Timed
