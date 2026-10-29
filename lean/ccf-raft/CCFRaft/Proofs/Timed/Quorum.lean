module

public import CCFRaft.Proofs.Timed.Acks
public import CCFRaft.Proofs.Timed.Config
public import CCFRaft.Proofs.Replication.Owing

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# A quorum commits a signature

With reconfiguration settled, the stable primary keeps one active configuration.
If it is the primary alone, a pending signature of the term would owe a
retirement confirmation, which settled reconfiguration rules out. Otherwise each
eligible member of a live quorum acknowledges the signature within one bound,
and one more acknowledgement, within a second bound, commits it.
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

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]
  [Proofs.Config.InitialConfiguration] {nodes : List NodeID}
  {trace : Trace W Liveness.Event}
  (admissible : Admissible Proofs.Config.INITIAL_CONFIGURATION nodes trace)

include admissible

/-- A single active configuration of a rooted log is committed, or is the root. -/
theorem single_index_le {log : List Entry} {commit : Nat} {configuration : Configuration}
    (rooted : log.take 1 = [Proofs.Config.GENESIS])
    (active : activeConfigurations log commit = [configuration])
    : configuration.index <= max commit 1 := by
  by_cases two : 2 <= (configurationHistory log).length
  · have := single_committed active two
    omega
  obtain ⟨rest, eq, _⟩ := configurationHistory_split log 1
  have head : configurationHistory (log.take 1) ≠ [] :=
    configurationHistory_ne_nil (root := Proofs.Config.GENESIS) (by simp [rooted])
      Proofs.Config.GENESIS_configured
  have member : configuration ∈ configurationHistory log :=
    (activeConfigurations_sublist log commit).subset (by rw [active]; simp)
  have restNil : rest = [] := by
    have length := congrArg List.length eq
    have := List.length_pos_iff.mpr head
    rw [List.length_append] at length
    exact List.eq_nil_of_length_eq_zero (by omega)
  rw [eq, restNil, List.append_nil] at member
  have := configurationHistory_index_le _ member
  have := List.length_take_le 1 log
  omega

/-- A signature of the term in the stable primary's log commits by `last`, if
every eligible member of a live quorum acknowledges within the timing facts. -/
theorem quorum_commits {start last : Nat} {stop delay interval : Real} {leader : NodeID}
    {term : Nat} (stable : StableLeader trace start leader term)
    (settled
      : forall index state,
          start <= index
          -> nodeAt trace index leader = some state
          -> Liveness.ReconfigurationSettled state)
    {quorum : Finset NodeID}
    (majority
      : forall state,
          nodeAt trace last leader = some state
          -> hasQuorum state.activeConfigurations quorum)
    (envs
      : forall peer,
          peer ∈ quorum
          -> Not (peer = leader)
          -> (forall index state,
                start <= index
                -> nodeAt trace index leader = some state
                -> peer ∈ eligiblePeers state leader)
          -> Env trace start last stop delay interval leader peer)
    (currents
      : forall peer,
          peer ∈ quorum
          -> Not (peer = leader)
          -> forall index point,
              start <= index
              -> index <= last
              -> trace.stateAt index = some point
              -> exists state,
                  nodeState (proto point) peer = some state /\ state.currentTerm = term)
    {backlog : Nat}
    (backlogs
      : forall peer,
          peer ∈ quorum
          -> Not (peer = leader)
          -> forall other primary,
              nodeAt trace start peer = some other
              -> nodeAt trace start leader = some primary
              -> ((primary.log.drop (agree other.log primary.log)).map
                    Entry.term).toFinset.card
                  <= backlog)
    (nonneg : 0 <= delay) (intervalNonneg : 0 <= interval)
    (lastFound : exists point, trace.stateAt last = some point) {signed : Nat}
    (startLe : start <= signed) (signedLe : signed <= last) {state : NodeState}
    {signature : Nat} (found : nodeAt trace signed leader = some state)
    (isSignature : isSignatureAt state.log signature = true)
    (signatureTerm : termAt state.log signature = term)
    (timely : clock trace signed + 2 * ackBound delay interval backlog <= stop)
    : exists later after,
        signed <= later
        /\ later <= last
        /\ nodeAt trace later leader = some after
        /\ signature <= after.commitIndex := by
  classical
  have single
      : forall index state,
          start <= index
          -> nodeAt trace index leader = some state
          -> state.activeConfigurations.length = 1 :=
    fun index state le found => (settled index state le found).1
  by_cases done : signature <= state.commitIndex
  · exact ⟨signed, state, le_rfl, signedLe, found, done⟩
  simp only [not_le] at done
  obtain ⟨config, activeAt⟩ := List.length_eq_one_iff.mp (single signed state startLe found)
  obtain ⟨positive, bound⟩ := le_length_of_isSignatureAt isSignature
  have rooted : state.log.take 1 = [Proofs.Config.GENESIS] := by
    obtain ⟨point, pointFound, nodeFound⟩ := nodeAt_eq_some.mp found
    obtain ⟨_, exec⟩ := exec_of_reachable (admissible.reachable pointFound)
    have inv := good_of_exec exec _ (List.suffix_refl _) (List.cons_ne_nil _ _)
    rcases inv.rooted leader state (Concrete.mem_of_nodeState nodeFound) with empty | head
    · rw [empty] at bound
      simp at bound
      omega
    · exact head
  have indexLe : config.index <= signature := by
    have := single_index_le admissible rooted activeAt
    omega
  have notAlone : Not (config.nodes = {leader}) := by
    intro alone
    obtain ⟨node, member⟩ :=
      confirmation_owed admissible found (stable.primary startLe found)
        (signature := signature)
        ⟨done, isSignature, by rw [signatureTerm, stable.current startLe found],
          ⟨config, by rw [activeAt]; simp, indexLe⟩,
          fun other member _ => by
            rw [activeAt, List.mem_singleton] at member
            rw [member]
            exact alone⟩
    rw [(settled signed state startLe found).2] at member
    simp at member
  have fixed
      : forall index other,
          start <= index
          -> nodeAt trace index leader = some other
          -> other.activeConfigurations = [config] := by
    rcases configuration_fixed admissible stable single with ⟨base, all⟩ | alone
    · intro index other le found'
      have same := all signed state startLe found
      rw [activeAt, List.cons.injEq] at same
      rw [all index other le found', ← same.1]
    · exact absurd (alone signed state config startLe found (by rw [activeAt]; simp)) notAlone
  have eligible
      : forall peer,
          peer ∈ config.nodes
          -> Not (peer = leader)
          -> forall index other,
              start <= index
              -> nodeAt trace index leader = some other
              -> peer ∈ eligiblePeers other leader := by
    intro peer member different index other le found'
    simp only [eligiblePeers, Finset.mem_erase]
    refine ⟨different, Finset.mem_union_left _ ?_⟩
    show peer ∈ configurationMembers other.activeConfigurations
    rw [fixed index other le found']
    exact mem_configurationMembers (List.mem_singleton_self _) member
  have boundNonneg : 0 <= ackBound delay interval backlog := by
    unfold ackBound
    positivity
  have round
      : forall peer,
          peer ∈ quorum
          -> peer ∈ config.nodes
          -> Not (peer = leader)
          -> exists delivered,
              signed < delivered
              /\ delivered < last
              /\ clock trace delivered <= clock trace signed + ackBound delay interval backlog
              /\ forall index other,
                  delivered < index
                  -> nodeAt trace index leader = some other
                  -> signature <= other.matchIndex peer := by
    intro peer inQuorum inConfig different
    have env := envs peer inQuorum different (eligible peer inConfig different)
    obtain ⟨later, step, reply, acked, lt, clockLe, stepped, event, envelope, ackedGe⟩ :=
      peer_acks admissible stable different env (currents peer inQuorum different)
        (eligible peer inConfig different) nonneg intervalNonneg
        (backlogs peer inQuorum different) startLe signedLe (by linarith)
    refine ⟨later, lt, env.ends _ _ stepped, clockLe, fun index other le found' => ?_⟩
    obtain ⟨_, before, beforeFound, _⟩ := stable.leads (by omega) (Trace.stateAt_of_stepAt stepped)
    have stateSucc : trace.stateAt (later + 1) = some step.after := by
      show (trace.stepAt later).map _ = _
      rw [stepped]
      rfl
    obtain ⟨_, after, afterFound, _⟩ := stable.leads (by omega) stateSucc
    have beforeAt : nodeAt trace later leader = some before := by
      rw [nodeAt_before stepped, beforeFound]
    have afterAt : nodeAt trace (later + 1) leader = some after := by
      rw [nodeAt_succ stepped, afterFound]
    have payload
        : reply.envelope.payload
          = .appendEntriesResponse { term, success := true, lastLogIndex := acked } := by
      rw [envelope]
    have source : reply.envelope.source = peer := by rw [envelope]
    have exact :=
      ack_exact admissible stable (by omega) stepped (envelope := reply.envelope)
        (by rw [event]; rfl) (by rw [envelope]) payload rfl le_rfl beforeFound afterFound
        (by rw [source]; exact eligible peer inConfig different later before (by omega) beforeAt)
    have ackedLe : acked <= after.matchIndex peer := by
      rw [← source, exact]
      exact le_max_right _ _
    have grows : after.matchIndex peer <= other.matchIndex peer :=
      match_mono admissible stable (by omega) le afterAt found'
    have := ackedGe state found
    omega
  obtain ⟨lastPoint, lastPointFound⟩ := lastFound
  obtain ⟨final, finalFound⟩ := stable.found (startLe.trans signedLe) lastPointFound
  have quorumConfig : hasConfigurationMajority quorum config :=
    hasQuorum_majority (majority final finalFound)
      (by rw [fixed last final (startLe.trans signedLe) finalFound]; simp)
  obtain ⟨witness, witnessQuorum, witnessConfig, witnessOther⟩ :=
    other_member quorumConfig notAlone
  choose! deliveredOf deliveredSpec using round
  let peers := (quorum.filter fun node => node ∈ config.nodes).erase leader
  have witnessPeer : witness ∈ peers := by
    simp only [peers, Finset.mem_erase, Finset.mem_filter]
    exact ⟨witnessOther, witnessQuorum, witnessConfig⟩
  obtain ⟨latest, latestPeer, latestMax⟩ :=
    Finset.exists_max_image peers deliveredOf ⟨witness, witnessPeer⟩
  have latestMem : latest ∈ quorum /\ latest ∈ config.nodes /\ Not (latest = leader) := by
    simp only [peers, Finset.mem_erase, Finset.mem_filter] at latestPeer
    exact ⟨latestPeer.2.1, latestPeer.2.2, latestPeer.1⟩
  obtain ⟨signedLt, latestLt, latestClock, _⟩ :=
    deliveredSpec latest latestMem.1 latestMem.2.1 latestMem.2.2
  set base := deliveredOf latest with baseEq
  have env := envs witness witnessQuorum witnessOther (eligible witness witnessConfig witnessOther)
  obtain ⟨later, step, reply, acked, lt, _, stepped, event, envelope, _⟩ :=
    peer_acks admissible stable witnessOther env (currents witness witnessQuorum witnessOther)
      (eligible witness witnessConfig witnessOther) nonneg intervalNonneg
      (backlogs witness witnessQuorum witnessOther) (by omega) latestLt.le (by linarith)
  have laterLt := env.ends _ _ stepped
  obtain ⟨_, current, currentFound, _⟩ := stable.leads (by omega) (Trace.stateAt_of_stepAt stepped)
  have nodeAt : nodeAt trace later leader = some current := by
    rw [nodeAt_before stepped, currentFound]
  have grown := stable_log_prefix admissible stable startLe (by omega) found nodeAt
  have ready : SignatureReady current leader signature := by
    refine ⟨bound.trans grown.length_le, ?_, ?_, ?_⟩
    · rw [isSignatureAt_of_prefix grown bound]
      exact isSignature
    · rw [termAt_of_prefix grown bound, stable.current (by omega) nodeAt, signatureTerm]
    · have activeEq := fixed later current (by omega) nodeAt
      unfold NodeState.activeMembers
      rw [activeEq, List.filter_singleton, show decide (config.index <= signature) = true by
        simp [indexLe], Bool.cond_true]
      refine hasQuorum_of_cover (small := quorum)
        ⟨List.cons_ne_nil _ _, by simp [quorumConfig]⟩
        fun configuration member node inQuorum inNodes => ?_
      rw [List.mem_cons, List.mem_nil_iff, or_false] at member
      subst member
      rw [Finset.mem_filter]
      refine ⟨mem_configurationMembers (List.mem_singleton_self _) inNodes, ?_⟩
      by_cases same : node = leader
      · exact Or.inl same
      · have nodePeer : node ∈ peers := by
          simp only [peers, Finset.mem_erase, Finset.mem_filter]
          exact ⟨same, inQuorum, inNodes⟩
        have := latestMax node nodePeer
        exact Or.inr ((deliveredSpec node inQuorum inNodes same).2.2.2 later current (by omega)
          nodeAt)
  obtain ⟨after, afterFound, committed⟩ :=
    ack_commits_trace admissible stable (by omega) stepped event (by rw [envelope])
      (by rw [envelope]) rfl le_rfl nodeAt
      (by
        rw [show reply.envelope.source = witness by rw [envelope]]
        exact eligible witness witnessConfig witnessOther later current (by omega) nodeAt)
      ready
  exact ⟨later + 1, after, by omega, by omega, afterFound, committed⟩

end CCFRaft.Proofs.Timed
