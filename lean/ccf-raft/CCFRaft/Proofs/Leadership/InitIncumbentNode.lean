module

public import CCFRaft.Proofs.Leadership.AnchorNode

@[expose] public section

set_option linter.unusedSectionVars false

/-!
Local primary knowledge and AppendEntries facts for an incumbent primary.
-/

open CCF.Execution (Trace)

namespace CCFRaft.Proofs.Leadership.InitIncumbent

open CCF
open Model.Node
open CCFRaft.Proofs.Safety
open CCFRaft.Proofs.Ledger

/-- A primary knows itself. -/
def Knows (state : NodeState) : Prop :=
  state.role = .primary -> state.primaryKnown = true

/-- Committing either preserves knowledge or clears the role. -/
theorem knows_record (self : NodeID) (state : NodeState) (index : Nat)
    (known : Knows state)
    : Knows (state.recordCommit self index) := by
  unfold NodeState.recordCommit
  dsimp only
  split
  · simp [Knows]
  · exact known

/-- Appending and committing received entries preserves primary knowledge. -/
theorem knows_from_primary (self : NodeID) (state : NodeState)
    (request : AppendEntriesRequest) (known : Knows state)
    : Knows (handleAppendEntiresFromPrimary self state request).1 := by
  unfold handleAppendEntiresFromPrimary
  dsimp only
  apply knows_record
  generalize request.entries.drop (state.log.length - request.prevLogIndex) = entries
  induction entries generalizing state with
  | nil => exact known
  | cons entry rest ih =>
      simp only [List.foldl_cons]
      apply ih
      split
      · exact knows_record _ _ _ known
      · exact known

section Steps

variable (self : NodeID)
local notation "caps" => (Capabilities.record self : Caps)

/-- A commit scan preserves primary knowledge. -/
theorem advance_known (state : NodeState) (known : Knows state)
    : Sends (fun after _ => Knows after) (advanceCommit caps state self) := by
  unfold advanceCommit
  dsimp only
  refine Sends.ite' (fun _ => Sends.pure' known) fun _ => ?_
  have recorded := knows_record self state (highestCommittableIndex state self) known
  refine Sends.ite' (fun _ => ?_) fun _ => Sends.pure' recorded
  exact Sends.ite'
    (fun _ => Sends.bind' (nominate_sends self state) fun _ _ _ => Sends.pure' recorded)
    fun _ => Sends.pure' recorded

/-- Becoming primary establishes primary knowledge. -/
theorem primary_known (state : NodeState)
    : Sends (fun after _ => Knows after) (becomePrimary caps self state) := by
  unfold becomePrimary
  refine Sends.bind' (advance_known self _ (fun _ => rfl)) fun _ _ known => ?_
  refine Sends.bind' (Sends.forIn' (R := fun _ => True) fun _ _ _ => ?_)
    fun _ _ _ => Sends.pure' known
  exact Sends.bind' (Sends.send _ _ _) fun _ _ _ => Sends.pure' (by simp)

/-- An election preserves the primary invariant. -/
theorem elect_known (state : NodeState) (known : Knows state)
    : Sends (fun after _ => Knows after) (electIfQuorum caps self state) := by
  unfold electIfQuorum
  exact Sends.ite' (fun _ => primary_known self state) fun _ => Sends.pure' known

/-- Campaigning establishes primary knowledge if it wins. -/
theorem candidate_known (state : NodeState)
    : Sends (fun after _ => Knows after) (becomeCandidate caps state self) := by
  unfold becomeCandidate
  refine Sends.bind' (elect_known self _ (by simp [Knows])) fun _ _ known => ?_
  exact Sends.bind' (broadcast_sends self _ _) fun _ _ _ => Sends.pure' known

/-- Observing a term preserves the primary invariant. -/
theorem observe_known (state : NodeState) (message : Message) (known : Knows state)
    : Knows (observeTerm state message) := by
  cases message <;> simp only [observeTerm, updateTerm] <;> (try split_ifs) <;>
    first | exact known | simp [Knows, becomeAwareOfNewTerm]

/-- Handling AppendEntries preserves the primary invariant. -/
theorem ae_known (source : NodeID) (state : NodeState) (request : AppendEntriesRequest)
    (known : Knows state)
    : Sends (fun after _ => Knows after)
        (handleAppendEntriesRequest caps self source state request) := by
  unfold handleAppendEntriesRequest
  dsimp only
  generalize hw : (if request.term = state.currentTerm
      /\ (state.role = .candidate \/ state.role = .preVoteCandidate) then
    becomeAwareOfNewTerm state request.term else state) = w
  have knownW : Knows w := by
    rw [← hw]
    split
    · simp [Knows, becomeAwareOfNewTerm]
    · exact known
  refine Sends.ite' (fun _ => ?_) fun _ => ?_
  · refine Sends.ite' (fun _ => ?_) fun _ => ?_ <;>
      exact Sends.bind' (Sends.send _ _ _) fun _ _ _ => Sends.pure' knownW
  refine Sends.ite' (fun _ => Sends.pure' (fun _ => rfl)) fun _ => ?_
  have tail : forall v : NodeState, Knows v ->
      Sends (fun after _ => Knows after)
        (do
          let (state, response) := handleAppendEntiresFromPrimary self v request
          (Capabilities.record self).send (.appendEntriesResponse response) source
          return state : NodeEffect _) := by
    intro v known
    have result := knows_from_primary self v request known
    obtain ⟨⟨next, response⟩, eq⟩ :
        exists p, handleAppendEntiresFromPrimary self v request = p := ⟨_, rfl⟩
    rw [eq] at result
    simp only [eq]
    exact Sends.bind' (Sends.send _ _ _) fun _ _ _ => Sends.pure' result
  split <;> exact tail _ (fun _ => rfl)

/-- Receiving a message preserves primary knowledge. -/
theorem receive_known (state : NodeState) (source : NodeID) (message : Message)
    (known : Knows state)
    : Sends (fun after _ => Knows after) (receive caps self source state message) := by
  have observed := observe_known state message known
  simp only [receive]
  refine Sends.ite' (fun _ => Sends.pure' known) fun _ => ?_
  cases message with
  | appendEntriesRequest request => exact ae_known self source _ request observed
  | appendEntriesResponse response =>
      unfold handleAppendEntriesResponse
      refine Sends.ite' (fun _ => Sends.pure' observed) fun _ => ?_
      refine Sends.ite' (fun _ => ?_) fun _ => Sends.pure' observed
      exact Sends.ite' (fun _ => advance_known self _ observed) fun _ => Sends.pure' observed
  | requestVoteRequest request =>
      unfold handleRequestVoteRequest
      exact Sends.bind' (Sends.send _ _ _)
        fun _ _ _ => Sends.pure' (by split <;> exact observed)
  | requestPreVoteRequest request =>
      unfold handleRequestPreVoteRequest
      exact Sends.bind' (Sends.send _ _ _) fun _ _ _ => Sends.pure' observed
  | requestVoteResponse response =>
      unfold handleRequestVoteResponse
      exact Sends.ite' (fun _ => elect_known self _ observed) fun _ => Sends.pure' observed
  | requestPreVoteResponse response =>
      unfold handleRequestPreVoteResponse
      refine Sends.ite' (fun _ => ?_) fun _ => Sends.pure' observed
      exact Sends.ite' (fun _ => candidate_known self _) fun _ => Sends.pure' observed
  | proposeRequestVoteRequest term =>
      unfold handleProposeRequestVoteRequest
      exact Sends.ite' (fun _ => candidate_known self _) fun _ => Sends.pure' observed

/-- A local action preserves primary knowledge. -/
theorem act_known (state : NodeState) (input : Input) (known : Knows state)
    : Sends (fun after _ => Knows after) (act caps self state input) := by
  cases input with
  | append contents =>
      simp only [act]
      unfold appendBatch
      refine Sends.bind' Sends.guard' fun _ sent ⟨_, empty⟩ => ?_
      subst empty
      refine Sends.bind'
        (Sends.mono
          (Sends.foldlM' (I := BatchState self state)
            (fun value sent' item batch =>
              appendEntry_batch self state value sent' item batch)
            contents state [] (BatchState.start self state))
          fun _ _ done => by simpa using done)
        fun appended _ batch => ?_
      obtain ⟨⟨entries, sentIndex, rfl, _, _⟩, _⟩ := batch
      exact advance_known self _ known
  | sendEntries destination batchEnds =>
      refine Sends.mono (sendEntries_pass self state destination batchEnds)
        fun after _ pass => ?_
      rw [pass.state]
      exact known
  | timeout kind =>
      cases kind with
      | election =>
          simp only [act]
          unfold startElection
          refine Sends.bind' Sends.guard' fun _ _ _ => ?_
          unfold becomePreVoteCandidate
          dsimp only
          refine Sends.ite' (fun _ => candidate_known self _) fun _ => ?_
          exact Sends.bind' (broadcast_sends self _ _)
            fun _ _ _ => Sends.pure' (by simp [Knows])
      | checkQuorum =>
          simp only [act]
          unfold checkQuorum
          exact Sends.bind' Sends.guard' fun _ _ _ => Sends.pure' (by simp [Knows])
  | nominateSuccessor =>
      exact Sends.mono (nominate_sends self state) fun _ _ ⟨eq, _⟩ => eq ▸ known

/-- Every local step preserves the primary invariant. -/
theorem step_known (state : NodeState) (event : Model.Node.Event) (known : Knows state)
    : Sends (fun after _ => Knows after) (Model.Node.step caps self state event) := by
  cases event with
  | internal input => exact act_known self state input known
  | receive source message => exact receive_known self state source message known

end Steps

section Trace

open CCF.MultiNodeTransitionSystem
open CCFRaft.Liveness
open CCFRaft.Proofs.Replication
open CCFRaft.Proofs.Liveness (Admissible)
open HasProtocol (proto)

variable [Config.InitialConfiguration]
  {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]
  {trace : Trace W Liveness.Event} {nodes : List NodeID}
  (admissible : Admissible Config.INITIAL_CONFIGURATION nodes trace)

include admissible

/-- Every reachable primary knows itself. -/
theorem knows_at {index : Nat} {point : W} (found : trace.stateAt index = some point)
    {node : NodeID} {state : NodeState}
    (nodeFound : nodeState (proto point) node = some state)
    : Knows state := by
  refine trace.induction (start := 0)
    (motive := fun _ point => forall node state,
      nodeState (proto point) node = some state -> Knows state)
    (fun point found node state nodeFound => ?_)
    (fun index step _ stepped held node state nodeFound => ?_)
    index point (Nat.zero_le _) found node state nodeFound
  · simp only [Trace.stateAt_zero, Option.some.injEq] at found
    subst point
    rw [initial_state admissible.protocol.init (Concrete.mem_of_nodeState nodeFound)]
    simp only [Knows, initialLocal]
    split_ifs <;> simp_all
  · cases selected : step.action.action with
    | none =>
        rw [admissible.stutter stepped selected] at nodeFound
        exact held node state nodeFound
    | some action =>
        obtain ⟨tr, _, _⟩ := transition_acts
          (admissible.step stepped selected)
        rcases tr.mem_after (Concrete.mem_of_nodeState nodeFound)
          with ⟨rfl, rfl⟩ | ⟨_, mem⟩
        · obtain ⟨_, _, known⟩ :=
            step_known tr.actor tr.pre tr.event (held _ _ tr.found) {} _ _ tr.ran
          exact known
        · exact held node state (Direct.nodeState_of_mem
            (Direct.keys_nodup (admissible.reachable_before stepped)) mem)

end Trace

end CCFRaft.Proofs.Leadership.InitIncumbent
