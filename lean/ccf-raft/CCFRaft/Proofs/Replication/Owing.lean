module

public import CCFRaft.Proofs.Replication.Sane

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# A primary alone owes a retirement confirmation

A primary that alone makes an uncommitted current-term signature committable
owes a retirement confirmation. The signature can only have become committable
without a commit scan during the scan that last advanced the commit index, and
that scan retired the other members of the configurations before it. None of
them has a confirmation in force, by `ConfSane`.
-/

open CCF
open CCFRaft.Model.Node
open CCFRaft.Liveness
open CCFRaft.Proofs.Safety

open CCF.Execution (Trace)

namespace CCFRaft.Proofs.Replication

variable [Config.InitialConfiguration]

/-- The invariant: a primary owes a confirmation whenever it alone makes an
uncommitted current-term signature committable. -/
def Owing (state : NodeState) (self : NodeID) : Prop :=
  state.role = .primary -> forall signature, AloneReady state self signature -> Owed state

theorem initial_owing (node : NodeID)
    : Owing (Model.initialNodeState Config.INITIAL_CONFIGURATION node) node := by
  intro _ signature alone
  have isSignature := alone.2.1
  exfalso
  simp only [Model.initialNodeState] at isSignature
  split at isSignature
  · rcases signature with _ | _ | signature <;>
      simp [isSignatureAt, entryAt?, EntryContent.isSignature] at isSignature
  · simp [isSignatureAt, entryAt?] at isSignature

namespace Ctx

variable {nodes : List NodeID} {after before : Model.State} {rest : History}
  (c : Ctx nodes after before rest)

include c

/-- The commit scan of a step leaves the primary owing. -/
theorem scan_owing {middle : NodeState} (advance : Advance c.actor middle c.post)
    (sane : ConfSane middle)
    : Owing c.post c.actor :=
  fun _ _ alone => advance_owed advance (fresh_of_sane sane) alone

theorem owing_post
    (owing : forall node state, Now (before :: rest) node state -> Owing state node)
    : Owing c.post c.actor := by
  intro primary signature alone
  have pre := sane_of_exec c.prior c.actor c.pre c.pre_seen
  have preFrontier := c.pre_seen.frontier c.prior
  have winning : Wins c.actor c.pre c.event c.post -> Owed c.post := by
    intro wins
    obtain ⟨candidate, campaign, _, advance⟩ := wins
    obtain ⟨_, candidateLog, candidateCommit, _⟩ := campaign
    have sub : (primaryState candidate).log <+: c.pre.log := by
      rw [← candidateLog]
      exact primaryState_log_prefix _
    exact Ctx.scan_owing c advance
      (pre.of_prefix sub (le_of_eq (candidateCommit.symm.trans rfl))) primary signature alone
  obtain ⟨_, _, _, _, leaderField, _, _, _⟩ := c.sum
  rcases leaderField primary with ⟨prePrimary, termEq⟩ | wins
  swap
  · exact winning wins
  cases Summary.kind c.sum with
  | same log commit =>
      have preAlone : AloneReady c.pre c.actor signature := by
        obtain ⟨below, isSignature, current, ⟨first, firstIn, firstLe⟩, single⟩ := alone
        unfold NodeState.activeConfigurations at firstIn single
        rw [log, commit] at firstIn single
        rw [commit] at below
        refine ⟨below, log ▸ isSignature, ?_, ⟨first, firstIn, firstLe⟩, single⟩
        rw [← log, ← termEq]
        exact current
      have owed := owing c.actor c.pre c.pre_now prePrimary signature preAlone
      unfold Owed NodeState.retirementCompletedNodes NodeState.committedLog at owed ⊢
      rw [log, commit]
      exact owed
  | append entries sent _ _ guarded advance =>
      exact Ctx.scan_owing c advance ((pre.batch preFrontier guarded).of_log rfl le_rfl)
        primary signature alone
  | ack _ _ _ _ _ _ advance =>
      exact Ctx.scan_owing c advance (pre.of_log rfl le_rfl) primary signature alone
  | elect wins => exact winning wins
  | accept source request eq accepted =>
      exfalso
      obtain ⟨earlier, sender, suffix, canon, aeok, _⟩ := c.accept_shape eq accepted
      have senderLed : Led (before :: rest) source request.term := canon.2.2.2.mono suffix
      have actorLed : Led (before :: rest) c.actor c.pre.currentTerm :=
        c.inv.leader_led c.actor c.pre c.pre_now prePrimary
      have termIs : request.term = c.pre.currentTerm := by
        rw [accepted.1, termEq]
      rw [termIs] at senderLed
      exact aeok.1 (c.inv.election_safety c.actor source _ actorLed senderLed)

end Ctx

/-- Every primary of every execution satisfies `Owing`. -/
theorem owing_of_exec {nodes : List NodeID} {history : History}
    (exec : Exec nodes history)
    : forall node state, Now history node state -> Owing state node := by
  induction exec with
  | @initial current initialized =>
      intro node state now
      have initial : state = Model.initialNodeState Config.INITIAL_CONFIGURATION node :=
        initialized.2.2.2.2 (node, state) now
      rw [initial]
      exact initial_owing node
  | step prior stepped ih =>
      obtain ⟨transition⟩ := LocalTransition.ofStep stepped
      have c : Ctx nodes _ _ _ := ⟨.step prior stepped, transition, good_of_exec prior⟩
      intro node state now
      rcases c.now_after now with ⟨rfl, rfl⟩ | ⟨_, old⟩
      · exact Ctx.owing_post c ih
      · exact ih node state old

/-- Along an admissible execution, a primary owes a retirement confirmation
whenever it alone makes an uncommitted current-term signature committable. -/
theorem confirmation_owed {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W]
    [HasNetwork W] {nodes : List NodeID} {trace : Trace W Liveness.Event}
    (admissible : Proofs.Liveness.Admissible Config.INITIAL_CONFIGURATION nodes trace)
    {leader : NodeID} {index : Nat} {state : NodeState}
    (found : nodeAt trace index leader = some state)
    (primary : state.role = .primary) {signature : Nat}
    (alone : AloneReady state leader signature)
    : Owed state := by
  obtain ⟨point, pointFound, nodeFound⟩ := nodeAt_eq_some.mp found
  obtain ⟨_, exec⟩ := exec_of_reachable (admissible.reachable pointFound)
  exact owing_of_exec exec leader state (Concrete.mem_of_nodeState nodeFound) primary signature
    alone

end CCFRaft.Proofs.Replication
