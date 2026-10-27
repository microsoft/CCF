module

public import CCFRaft.Properties.Liveness.Assumptions.Window
public import CCFRaft.Proofs.Liveness.Trace
public import Mathlib.Data.Finset.Order

@[expose] public section

/-!
# Facts at the start of a commit window

Facts about a recording and the start index of a window, independent of how the
primary got there. A diverging clock records a step, and so a state, at every
index. A primary whose log is a prefix of every participant's log has no backlog.
-/

open CCF.Execution (Trace)

namespace CCFRaft.Proofs.Liveness

open CCFRaft.Liveness
open Model.Node
open CCF.MultiNodeTransitionSystem (nodeState)
open HasProtocol (proto)
open HasTime (time)

/-- A log agrees with any extension of it throughout. -/
theorem agreedPrefix_of_prefix {leaderLog followerLog : List Entry}
    (sub : leaderLog <+: followerLog)
    : agreedPrefix leaderLog followerLog = leaderLog.length := by
  obtain ⟨rest, rfl⟩ := sub
  induction leaderLog with
  | nil => simp [agreedPrefix]
  | cons entry log ih => simp_all [agreedPrefix]

section Backlog

variable {W : Type} [HasProtocol W Model.State] {trace : Trace W Liveness.Event}
  {start : Nat} {leader : NodeID} {participants : Finset NodeID}

/-- A primary whose log at `start` is a prefix of every participant's log has no
backlog: nothing lies beyond the agreed prefix. -/
theorem backlogTerms_zero_of_prefix
    (caughtUp
      : forall first leaderState follower followerState,
          trace.stateAt start = some first
          -> nodeState (proto first) leader = some leaderState
          -> follower ∈ participants
          -> nodeState (proto first) follower = some followerState
          -> leaderState.log <+: followerState.log)
    : BacklogTerms trace start leader participants 0 := by
  intro _ _ _ _ found leaderFound member followerFound
  simp [agreedPrefix_of_prefix (caughtUp _ _ _ _ found leaderFound member followerFound)]

/-- Equal logs at `start` leave the primary no backlog. -/
theorem backlogTerms_zero_of_log_eq
    (same
      : forall first leaderState follower followerState,
          trace.stateAt start = some first
          -> nodeState (proto first) leader = some leaderState
          -> follower ∈ participants
          -> nodeState (proto first) follower = some followerState
          -> followerState.log = leaderState.log)
    : BacklogTerms trace start leader participants 0 :=
  backlogTerms_zero_of_prefix
    fun _ _ _ _ found leaderFound member followerFound => by
      simp [same _ _ _ _ found leaderFound member followerFound]

end Backlog

end CCFRaft.Proofs.Liveness
