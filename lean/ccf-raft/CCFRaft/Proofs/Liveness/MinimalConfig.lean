module

public import CCFRaft.Proofs.Leadership.AnchorWindow

import all Init.Control.State

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# Configurations name only listed nodes

When the initial configuration and every appended configuration name only listed
nodes, so does every configuration in a log or an in-flight AppendEntries request
of a recorded state, and each is nonempty. `appendEntry` rejects an empty
configuration, and a step adds to its actor's log only the entries it appends or
receives in an AppendEntries request.
-/

open CCF.Execution (Trace)

namespace CCFRaft.Proofs.Liveness

open CCFRaft.Liveness
open CCF CCF.MultiNodeTransitionSystem
open Model.Node
open CCFRaft.Proofs.Safety
open CCFRaft.Proofs.Replication
open CCFRaft.Proofs.Direct (Keeps)
open CCFRaft.Proofs.CommitLiveness (append_log)
open HasProtocol (proto)

/-- The configuration an entry names, if any, is nonempty and names only `nodes`. -/
def ConfigOk (nodes : List NodeID) (entry : Entry) : Prop :=
  forall members,
    entry.content.metadata.configuration = some members
    -> members.Nonempty /\ members ⊆ nodes.toFinset

/-- Every entry of every log, and of every AppendEntries request in flight, names
an acceptable configuration. -/
structure ConfigsOk (nodes : List NodeID) (state : Model.State) : Prop where
  logs
    : forall node local_,
        (node, local_) ∈ state.nodes
        -> forall entry, entry ∈ local_.log -> ConfigOk nodes entry
  requests
    : forall envelope request,
        envelope ∈ state.network
        -> envelope.payload = .appendEntriesRequest request
        -> forall entry, entry ∈ request.entries -> ConfigOk nodes entry

section Append

variable (caps : Caps) (self : NodeID)

/-- `appendEntry` accepts only a nonempty configuration. -/
theorem appendEntry_nonempty (state : NodeState) (content : EntryContent)
    : Keeps
        (fun _ =>
          forall members,
            content.metadata.configuration = some members -> members.Nonempty)
        (appendEntry caps self state content) := by
  unfold appendEntry
  simp only [pure_bind]
  repeat'
    first
    | exact Keeps.pure' fun _ _ => by simp_all
    | refine Keeps.ite' (fun _ => ?_) fun _ => ?_
    | refine Keeps.bind' Keeps.guard' fun _ _ => ?_
    | refine Keeps.seq' fun _ => ?_
    | split

theorem foldAppend_nonempty
    : forall (contents : List EntryContent) (state : NodeState),
        Keeps
          (fun _ =>
            forall content,
              content ∈ contents
              -> forall members,
                  content.metadata.configuration = some members -> members.Nonempty)
          (contents.foldlM (appendEntry caps self) state)
  | [], _ => by
      simp only [List.foldlM_nil]
      exact Keeps.pure' (by simp)
  | content :: rest, state => by
      simp only [List.foldlM_cons]
      exact Keeps.bind' (appendEntry_nonempty caps self state content) fun middle head =>
        (foldAppend_nonempty rest middle).mono fun _ tail item member => by
          rcases List.mem_cons.mp member with rfl | member
          · exact head
          · exact tail item member

/-- An append batch accepts only nonempty configurations. -/
theorem append_nonempty (state : NodeState) (contents : List EntryContent)
    : Keeps
        (fun _ =>
          forall content,
            content ∈ contents
            -> forall members,
                content.metadata.configuration = some members -> members.Nonempty)
        (act caps self state (.append contents)) := by
  unfold act appendBatch
  exact Keeps.seq' fun _ => Keeps.bind' (foldAppend_nonempty caps self contents state)
    fun _ nonempty => (Keeps.trivial' _).mono fun _ _ => nonempty

end Append

theorem mem_acceptLog {log : List Entry} {request : AppendEntriesRequest} {entry : Entry}
    (member : entry ∈ acceptLog log request)
    : entry ∈ log \/ entry ∈ request.entries := by
  unfold acceptLog at member
  rcases List.mem_append.mp member with kept | new
  · left
    revert kept
    split
    · exact List.mem_of_mem_take
    · exact id
  · exact Or.inr (List.mem_of_mem_drop new)

theorem mem_primaryState_log {state : NodeState} {entry : Entry}
    (member : entry ∈ (primaryState state).log)
    : entry ∈ state.log := by
  unfold primaryState at member
  dsimp only at member
  split at member
  · exact List.mem_of_mem_take member
  · exact member

section Step

variable [Config.InitialConfiguration] {nodes : List NodeID} {after before : Model.State}
  {rest : History} (c : Ctx nodes after before rest)

include c

/-- An entry a step adds to its actor's log is one the step appends, of a
nonempty configuration if any, or one of a received AppendEntries request. -/
theorem post_entry {entry : Entry} (member : entry ∈ c.post.log)
    : entry ∈ c.pre.log
      \/ (exists contents,
            c.event = .internal (.append contents)
            /\ entry.content ∈ contents
            /\ forall members,
                entry.content.metadata.configuration = some members -> members.Nonempty)
      \/ exists source request,
          c.event = .receive source (.appendEntriesRequest request)
          /\ entry ∈ request.entries := by
  cases Summary.kind c.sum with
  | same log _ =>
      rw [log] at member
      exact Or.inl member
  | append _ _ _ _ _ _ appending =>
      obtain ⟨contents, eventEq⟩ := appending
      have ran := c.tr.ran
      rw [show c.tr.event = _ from eventEq] at ran
      have logEq := (append_log c.tr.actor c.tr.pre contents _ _ _ ran).1
      have nonempty :=
        append_nonempty (Capabilities.record c.tr.actor) c.tr.actor c.tr.pre contents _ _ _ ran
      have member' : entry ∈ c.tr.post.log := member
      rw [logEq] at member'
      rcases List.mem_append.mp member' with old | new
      · exact Or.inl old
      · obtain ⟨content, contentIn, rfl⟩ := List.mem_map.mp new
        exact Or.inr (Or.inl ⟨contents, eventEq, contentIn, nonempty content contentIn⟩)
  | ack _ _ _ _ _ _ advance =>
      rw [advance.log] at member
      exact Or.inl member
  | accept source request received accepted =>
      rw [accepted.2.2.2.2.2.1] at member
      rcases mem_acceptLog member with old | new
      · exact Or.inl old
      · exact Or.inr (Or.inr ⟨source, request, received, new⟩)
  | elect elected =>
      obtain ⟨candidate, campaign, _, advance⟩ := elected
      rw [advance.log] at member
      rw [← campaign.2.1]
      exact Or.inl (mem_primaryState_log member)

/-- A step keeps `ConfigsOk` when every configuration it appends names only
listed nodes. -/
theorem ConfigsOk.step (held : ConfigsOk nodes before)
    (appends
      : forall contents,
          c.event = .internal (.append contents)
          -> forall content,
              content ∈ contents
              -> forall members,
                  content.metadata.configuration = some members
                  -> members ⊆ nodes.toFinset)
    : ConfigsOk nodes after := by
  have postOk : forall entry, entry ∈ c.post.log -> ConfigOk nodes entry := by
    intro entry member
    rcases post_entry c member with old | ⟨contents, eventEq, contentIn, nonempty⟩
      | ⟨source, request, eventEq, entryIn⟩
    · exact held.logs _ _ c.pre_now entry old
    · intro members some
      exact ⟨nonempty members some, appends contents eventEq _ contentIn members some⟩
    · obtain ⟨envelope, pending, _, _, payload⟩ := c.received eventEq
      exact held.requests envelope request pending payload entry entryIn
  refine ⟨fun node local_ member => ?_, fun envelope request pending payload => ?_⟩
  · rcases c.now_after member with ⟨_, rfl⟩ | ⟨_, now⟩
    · exact postOk
    · exact held.logs node local_ now
  · rcases c.tr.mem_network pending with old | new
    · exact held.requests envelope request old payload
    · obtain ⟨_, ok⟩ := Summary.sends c.sum envelope new
      simp only [payload] at ok
      intro entry entryIn
      exact postOk entry (List.mem_of_mem_drop (ok.1.2.2.2.2.1.subset entryIn))

end Step

section Trace

variable [Config.InitialConfiguration]
  {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]
  {trace : Trace W Liveness.Event} {nodes : List NodeID}
  (admissible : Admissible Config.INITIAL_CONFIGURATION nodes trace)
  (initial : Config.INITIAL_CONFIGURATION ⊆ nodes.toFinset)
  (appends
    : forall index step node entries entry members,
        trace.stepAt index = some step
        -> step.action = .local node (.append entries)
        -> entry ∈ entries
        -> entry.metadata.configuration = some members
        -> members ⊆ nodes.toFinset)

include admissible initial appends

/-- At every recorded state, every configuration in a log or an in-flight
AppendEntries request is nonempty and names only listed nodes. -/
theorem configsOk {index : Nat} {point : W} (found : trace.stateAt index = some point)
    : ConfigsOk nodes (proto point) := by
  refine trace.induction (start := 0)
    (motive := fun _ point => ConfigsOk nodes (proto point)) ?_ ?_ index point
    (Nat.zero_le _) found
  · intro point found
    rw [Trace.stateAt_zero, Option.some.injEq] at found
    subst found
    obtain ⟨nonempty, _, _, network, inits⟩ := admissible.protocol.1
    refine ⟨fun node local_ member entry entryIn members some => ?_,
      fun envelope _ pending => ?_⟩
    · have localEq : local_ = Model.initialNodeState Config.INITIAL_CONFIGURATION node :=
        inits (node, local_) member
      subst localEq
      simp only [Model.initialNodeState] at entryIn
      split at entryIn
      · rw [List.mem_singleton] at entryIn
        subst entryIn
        cases some
        exact ⟨nonempty, initial⟩
      · cases entryIn
    · rw [network] at pending
      cases pending
  · intro index step _ stepped held
    cases selected : step.action.action with
    | none =>
        rw [admissible.stutter stepped selected]
        exact held
    | some action =>
        obtain ⟨rest, c, acts, _⟩ := ctx_at admissible stepped selected
        exact held.step c fun contents eventEq content contentIn members some =>
          appends index step c.actor contents content members stepped
            (Leadership.anchor_local_of_internal selected acts eventEq) contentIn some

/-- Every configuration of a recorded node's log is nonempty and names only
listed nodes. -/
theorem configuration_ok {index : Nat} {point : W}
    (found : trace.stateAt index = some point) {node : NodeID} {local_ : NodeState}
    (nodeFound : nodeState (proto point) node = some local_)
    {configuration : Configuration}
    (member : configuration ∈ configurationHistory local_.log)
    : configuration.nodes.Nonempty /\ configuration.nodes ⊆ nodes.toFinset := by
  obtain ⟨_, entry, get, some, _⟩ := Leadership.mem_history_iff.mp member
  exact (configsOk admissible initial appends found).logs node local_
    (now_of_found nodeFound (rest := [])) entry (List.mem_of_getElem? get) _ some

end Trace

end CCFRaft.Proofs.Liveness
