module

public import CCFRaft.Proofs.Liveness.Minimal
public import CCFRaft.Proofs.Liveness.MinimalConfig
public import CCFRaft.Proofs.Liveness.MinimalEngine
public import CCFRaft.Proofs.Leadership.InitIncumbentNode

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# Commit liveness from a minimal start

The primary and the members of its latest configuration anchor the term. At a
caught-up start they meet `MinInv`, so they form an anchor engine for half an
election timeout. The engine gives a stable window over the anchor in which the
term stays quiet among all listed nodes, so every node keeps a plain extension of
the primary's starting log and its reconfiguration stays settled. The timed commit
theorem then commits the request within `commitDuration` with no backlog.
-/

open CCF.Execution (Trace)

namespace CCFRaft.Proofs.Liveness

open CCFRaft.Liveness
open CCF CCF.MultiNodeTransitionSystem
open Model.Node
open CCFRaft.Proofs.Safety
open CCFRaft.Proofs.Replication
open CCFRaft.Proofs.Leadership
open HasProtocol (proto)
open HasTime (time)
open HasLive (live)
open HasTimers (deadline)

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]
  [HasTimers W]

/-- A caught-up primary commits a request it holds within `commitDuration` with no
backlog, when the election timeout exceeds twice `11 * maxDelay + 7 * heartbeat`. -/
theorem commit_minimal {config : Finset NodeID} {nodes : List NodeID} {bounds : Bounds}
    {maxDelay : Real} {trace : Trace W Liveness.Event} {start : Nat} {leader : NodeID}
    {request : ReqID}
    (protocol : Satisfies trace (protocolModel config nodes))
    (initial : config ⊆ nodes.toFinset)
    (appends
      : forall index step node entries entry members,
          trace.stepAt index = some step
          -> step.action = .local node (.append entries)
          -> entry ∈ entries
          -> entry.metadata.configuration = some members
          -> members ⊆ nodes.toFinset)
    (timing : Satisfies trace timingModel)
    (diverges : TimeDiverges trace)
    (crash : Satisfies trace crashModel)
    (delivery : Satisfies trace (deliveryModel config nodes))
    (bounded : Satisfies trace (boundedDelayModel maxDelay))
    (heartbeat : HeartbeatScheduling trace (some bounds.heartbeatInterval))
    (signature : SignatureScheduling trace (some bounds.signatureInterval))
    (scheduling : CheckQuorumScheduling trace bounds.electionTimeout)
    (elections : ElectionScheduling trace (some (bounds.electionTimeout / 2)) none)
    (constraints
      : 11 * maxDelay + 7 * max bounds.heartbeatInterval 0 < bounds.electionTimeout / 2)
    {first : W} {leaderState : NodeState}
    (firstFound : trace.stateAt start = some first)
    (leaderFound : nodeState (proto first) leader = some leaderState)
    (primary : leaderState.role = .primary)
    (has : HasRequest leaderState.log request)
    (settled : ReconfigurationSettled leaderState)
    (never
      : forall node,
          (node = leader \/ node ∈ leaderState.activeMembers)
          -> retirementIndexInLog node leaderState.log = none)
    (noProposal
      : forall packet,
          packet ∈ HasNetwork.pending first
          -> Not
              (packet.envelope.payload
                = .proposeRequestVoteRequest leaderState.currentTerm))
    (caughtUp
      : forall node,
          node ∈ nodes
          -> exists state,
              nodeState (proto first) node = some state
              /\ node ∈ live first
              /\ state.currentTerm = leaderState.currentTerm
              /\ state.log = leaderState.log
              /\ (node = leader \/ (state.role = .follower /\ state.primaryKnown = true))
              /\ (node = leader
                  \/ time first + bounds.electionTimeout / 2 <= deadline first node)
              /\ (node = leader
                  \/ AckedAfter trace start leader node
                      (time first - bounds.heartbeatInterval)))
    (noCrash
      : forall index step node,
          start <= index
          -> trace.stepAt index = some step
          -> Not (step.action = .crash node))
    (noDrop
      : forall index step packet,
          start <= index
          -> trace.stepAt index = some step
          -> Not (step.action = .drop packet))
    (noNominate
      : forall index step node,
          start <= index
          -> trace.stepAt index = some step
          -> Not (step.action = .local node .nominateSuccessor))
    (plain
      : forall index step node entries entry,
          start <= index
          -> trace.stepAt index = some step
          -> step.action = .local node (.append entries)
          -> entry ∈ entries
          -> entry.metadata.configuration = none)
    : exists index,
        Within trace start (Timed.commitDuration bounds maxDelay 0) index
        /\ RequestCommitted trace leader request index := by
  let _ : Config.InitialConfiguration := ⟨config⟩
  have admissible : Admissible Config.INITIAL_CONFIGURATION nodes trace :=
    ⟨protocol, timing, crash, delivery⟩
  have nonneg : 0 <= maxDelay := bounded.init.1
  have intervalNonneg : 0 <= max bounds.heartbeatInterval 0 := le_max_right _ _
  obtain ⟨anchor, anchorEq⟩
      : exists anchor : Finset NodeID,
          anchor = insert leader (latestConfigurationMembers (configurationHistory leaderState.log)) :=
    ⟨_, rfl⟩
  have latest : latestConfigurationMembers (configurationHistory leaderState.log) ⊆ anchor :=
    fun node member => anchorEq ▸ Finset.mem_insert_of_mem member
  have leaderIn : leader ∈ anchor := anchorEq ▸ Finset.mem_insert_self _ _
  have listed : forall node, node ∈ nodes -> node ∈ nodes.toFinset :=
    fun _ member => List.mem_toFinset.mpr member
  have leaderListed : leader ∈ nodes :=
    listed_of_mem admissible firstFound (Concrete.mem_of_nodeState leaderFound)
  -- Every configuration of the primary's log names only listed nodes.
  have latestListed
      : latestConfigurationMembers (configurationHistory leaderState.log) ⊆ nodes.toFinset := by
    intro node member
    cases lastEq : (configurationHistory leaderState.log).getLast? with
    | none =>
        rw [latestConfigurationMembers, lastEq] at member
        simp at member
    | some last =>
        rw [latestConfigurationMembers, lastEq] at member
        exact (configuration_ok admissible initial appends firstFound leaderFound
          (List.mem_of_getLast? lastEq)).2 member
  have subset : anchor ⊆ nodes.toFinset := by
    intro node member
    rw [anchorEq, Finset.mem_insert] at member
    rcases member with rfl | member
    · exact listed _ leaderListed
    · exact latestListed member
  have neverIn
      : forall node, node ∈ anchor -> retirementIndexInLog node leaderState.log = none := by
    intro node member
    rw [anchorEq, Finset.mem_insert] at member
    rcases member with rfl | member
    · exact never _ (.inl rfl)
    · exact never _ (.inr (latest_subset_active leaderState member))
  -- Every node at `start` is the primary or a follower knowing it, in its term
  -- with its log.
  obtain ⟨_, exec⟩ := history_at admissible firstFound
  have unique
      : forall node local_ state,
          (node, local_) ∈ (proto first).nodes
          -> nodeState (proto first) node = some state
          -> local_ = state := by
    intro node local_ state member found
    rw [found_of_now exec member] at found
    exact Option.some.inj found
  have lookup
      : forall node local_,
          (node, local_) ∈ (proto first).nodes
          -> local_.currentTerm = leaderState.currentTerm
            /\ local_.log = leaderState.log
            /\ ((node = leader /\ local_ = leaderState)
                \/ (local_.role = .follower /\ local_.primaryKnown = true)) := by
    intro node local_ member
    obtain ⟨state, found, _, term, log, role, _⟩ :=
      caughtUp node (listed_of_mem admissible firstFound member)
    obtain rfl := unique node local_ state member found
    refine ⟨term, log, ?_⟩
    rcases role with leaderEq | follower
    · exact .inl ⟨leaderEq, unique _ _ _ member (leaderEq ▸ leaderFound)⟩
    · exact .inr follower
  have notPreVote
      : forall node local_,
          (node, local_) ∈ (proto first).nodes -> Not (local_.role = .preVoteCandidate) := by
    intro node local_ member role
    rcases (lookup node local_ member).2.2 with ⟨_, rfl⟩ | ⟨follower, _⟩
    · rw [primary] at role
      cases role
    · rw [follower] at role
      cases role
  -- The primary's single active configuration is its latest, inside the anchor.
  have quorum : hasQuorum leaderState.activeConfigurations anchor := by
    obtain ⟨single, _⟩ := settled
    obtain ⟨configuration, activeEq⟩ := List.length_eq_one_iff.mp single
    have inHistory : configuration ∈ configurationHistory leaderState.log := by
      have member : configuration ∈ leaderState.activeConfigurations := by
        rw [activeEq]
        exact List.mem_singleton_self _
      unfold NodeState.activeConfigurations activeConfigurations at member
      exact List.mem_of_mem_drop member
    have latestEq
        : configuration.nodes
          = latestConfigurationMembers (configurationHistory leaderState.log) := by
      rw [← latest_active leaderState.log leaderState.commitIndex]
      have : activeConfigurations leaderState.log leaderState.commitIndex = [configuration] :=
        activeEq
      rw [this]
      simp [latestConfigurationMembers]
    have covered : configuration.nodes ⊆ anchor := latestEq ▸ latest
    have nonempty :=
      (configuration_ok admissible initial appends firstFound leaderFound inHistory).1
    rw [activeEq]
    refine ⟨List.cons_ne_nil _ _, ?_⟩
    simp only [List.all_cons, List.all_nil, Bool.and_true, decide_eq_true_eq,
      hasConfigurationMajority]
    rw [Finset.inter_eq_right.mpr covered]
    have := nonempty.card_pos
    omega
  have initialInv
      : MinInv nodes.toFinset anchor leader leaderState.currentTerm leaderState.log
          (time first + bounds.electionTimeout / 2) first := by
    refine ⟨⟨⟨?_, ?_, ?_⟩, ⟨subset, leaderIn, ?_, ?_, ?_, ?_⟩, ?_⟩, ?_, ?_, ?_⟩
    · exact fun node local_ member _ => (lookup node local_ member).1.le
    · intro envelope inNetwork _ _
      obtain ⟨sender, senderIn, le⟩ :=
        Duel.Elected.network_terms (admissible.reachable firstFound) envelope inNetwork
      exact le.trans (lookup _ _ senderIn).1.le
    · exact ⟨leaderState, Concrete.mem_of_nodeState leaderFound, primary, rfl⟩
    · intro local_ member
      rw [unique _ _ _ member leaderFound]
      exact quorum
    · intro local_ member node nodeIn different
      rw [unique _ _ _ member leaderFound]
      rw [anchorEq, Finset.mem_insert] at nodeIn
      unfold NodeState.activeConfigurations
      rw [latest_active]
      exact nodeIn.resolve_left different
    · intro node nodeIn
      obtain ⟨state, found, _, term, _, role, _⟩ :=
        caughtUp node (List.mem_toFinset.mp (subset nodeIn))
      refine ⟨state, Concrete.mem_of_nodeState found, term, ?_⟩
      rcases role with rfl | ⟨follower, known⟩
      · rw [leaderFound, Option.some.injEq] at found
        subst found
        exact ⟨InitIncumbent.knows_at admissible firstFound leaderFound primary, .inr primary⟩
      · exact ⟨known, .inl follower⟩
    · exact fun node local_ member _ role => absurd role (notPreVote node local_ member)
    · intro node local_ member nodeIn
      exact not_retired_of_history (by rw [(lookup node local_ member).2.1])
        (neverIn node nodeIn)
    · exact fun packet inPending _ _ => noProposal packet inPending
    · intro node local_ member
      obtain ⟨term, log, _⟩ := lookup node local_ member
      exact ⟨term, log ▸ ExtendsPlain.refl _⟩
    · exact fun node local_ member role => absurd role (notPreVote node local_ member)
  have good :=
    minimal_good admissible noCrash firstFound
      (fun node member => by
        obtain ⟨_, _, alive, _⟩ := caughtUp node member
        exact alive)
      noDrop noNominate plain
      (Timed.commitDuration bounds maxDelay 0)
  have behind : BacklogTerms trace start leader anchor 0 :=
    backlogTerms_zero_of_log_eq fun point local_ follower state found leaderAt member at_ => by
      rw [firstFound, Option.some.injEq] at found
      subst point
      rw [leaderFound, Option.some.injEq] at leaderAt
      subst local_
      obtain ⟨state', found', _, _, log, _⟩ := caughtUp follower (List.mem_toFinset.mp (subset member))
      rw [at_, Option.some.injEq] at found'
      subst state'
      exact log
  have late
      : forall index step node,
          start <= index
          -> trace.stepAt index = some step
          -> step.action = .local node (.timeout .election)
          -> Not (node = leader)
          -> time first + bounds.electionTimeout / 2 <= time step.before := by
    intro index step node afterStart stepped fires different
    have selected : step.action.action = some (.local node (.timeout .election)) := by
      rw [fires]
      rfl
    obtain ⟨_, c, ⟨actorEq, _⟩, _⟩ := ctx_at admissible stepped selected
    have nodeListed : node ∈ nodes :=
      actorEq ▸ listed_of_mem admissible (Trace.stateAt_of_stepAt stepped) c.pre_now
    obtain ⟨_, _, _, _, _, _, deadlineLate, _⟩ := caughtUp node nodeListed
    exact timeout_late timing elections.timeouts firstFound
      (deadlineLate.resolve_left different) afterStart stepped fires
  have engine :=
    minimal_engine admissible diverges bounded nonneg heartbeat scheduling
      (by linarith) (by linarith) good listed behind latest neverIn firstFound initialInv
      (fun peer peerIn different => by
        obtain ⟨_, _, _, _, _, _, _, acked⟩ := caughtUp peer (List.mem_toFinset.mp (subset peerIn))
        exact acked.resolve_left different)
      late
  have repairEq
      : repair maxDelay (max bounds.heartbeatInterval 0) 0
        = 10 * maxDelay + 6 * max bounds.heartbeatInterval 0 := by
    unfold repair
    push_cast
    ring
  obtain ⟨stable, stableTerm⟩ :=
    stable_window_catchup_engine admissible elections.timeouts bounded diverges nonneg heartbeat
      (backlog := 0) (by rw [repairEq]; linarith) le_rfl engine good behind
  have synced :=
    synced_window admissible good (listed _ leaderListed) listed stableTerm firstFound
      initialInv.synced
  have inTerm : InTermAt trace start leaderState.currentTerm anchor := by
    intro follower member
    obtain ⟨state, found, _, term, _⟩ := caughtUp follower (List.mem_toFinset.mp (subset member))
    exact ⟨first, state, firstFound, found, term⟩
  exact commit_of_stable protocol timing crash delivery bounded diverges
    heartbeat signature inTerm (.inl ⟨first, leaderState, firstFound, leaderFound, has⟩)
    behind stable (settled_window admissible firstFound leaderFound settled synced)

end CCFRaft.Proofs.Liveness
