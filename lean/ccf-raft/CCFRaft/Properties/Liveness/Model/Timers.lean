module

public import CCFRaft.Properties.Liveness.Model.Scheduling

@[expose] public section

/-!
# Election timers with explicit deadlines

`ElectionScheduling minimum jitter` owns election deadline validity, eventual
timeout execution and optional jitter bounds. `timingModel` owns clock advancement.
The scheduling contract's `ElectionTimeouts` component constrains deadline resets
and forbids early firing, without imposing progress by itself.
`Liveness.run` builds a run that takes the `j`-th participant reset's draw from a
sample (`Liveness.Sample`); the commit-liveness witness uses it.
-/

open CCF.Execution (Trace)

namespace CCFRaft.Liveness

open Model.Node
open HasProtocol (proto)
open HasTime (time)
open HasLive (live)

/-- Each node's pending election deadline, drawn when its timer is reset. -/
class HasTimers (W : Type) where
  deadline : W -> NodeID -> Real

open HasTimers (deadline)

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasTimers W]

/-- The validity component of election scheduling. With `minimum = some m`,
a reset draws a deadline between `m` and `2 * m` after its before-time.
`none` leaves that interval unconstrained. Deadlines change only on resets,
and a node times out only once its deadline has passed.
With the timing model this implies `ElectionSpacing minimum`; it does not
impose progress. Initial deadlines are unconstrained.
Use `some (electionTimeout / 2)` for CCF's configured election timeout.

Risk: this is a precondition about CCF's host driver, not a refinement of it.
CCF keeps no real-time deadline. `restart_election_timeout` (`raft.h`) sets
`timeout_elapsed` to a whole number of milliseconds drawn uniformly from
`[0, election_timeout / 2]`. `periodic` runs every `tick_interval` on the node's
own job-board clock, adds the time since its last run, and starts an election
once `timeout_elapsed >= election_timeout`, if the node is `ticking` and its
retirement is not committed. The differences:
- Ticks. A timeout fires at a tick, so up to a tick after the ideal deadline,
  and later still if ticks run late under load. The first tick after a reset
  also counts the time before the reset, so a timeout can also fire up to a
  tick early. `Bounds.electionTimeout` absorbs the early side. The late side is
  unbounded in CCF; `ElectionScheduling` can additionally bound it through jitter.
- Clocks. Deadlines here are on the one global `time`, whereas each CCF node
  measures elapsed time on its own clock, so drift moves real deadlines.
- Gating. CCF never times out before `start_ticking`, which runs the first time
  the node appends a signature while it is in its latest configuration, and
  stays on. `canStartElection` instead checks membership of a signed active
  configuration at each timeout. The two are close but not the same, and the
  difference is not modelled.
- Resets. Becoming primary zeroes `timeout_elapsed`, which then counts towards
  the heartbeat `request_timeout`, not an election. Here a primary keeps a stale
  deadline, which is harmless: a primary cannot time out, and in both every way
  out of primary either draws afresh (`become_follower`, on a later term or a
  failed quorum check) or commits the node's retirement, after which it never
  times out. `start_ticking` also zeroes it, without a draw, so until its next
  reset a newly ticking node is due after the full `election_timeout`: the top
  of the range, not a uniform draw.
Why the risk is accepted: the properties are about the protocol, not the
driver. `Properties.commit_liveness` uses only the lower end, which CCF meets
once `Bounds.electionTimeout` allows for ticks and drift. No theorem uses the
upper end or the draw distribution, so none is exposed to late ticks, drift or
the `start_ticking` reset.
Per-node clocks are future work (`README.md`). -/
structure ElectionTimeouts (trace : Trace W Event) (minimum : Option Real) : Prop where
  next
    : forall {index : Nat} {step : CCF.Execution.Step W Event},
        trace.stepAt index = some step
        -> forall node,
            (ElectionReset step node
              -> match minimum with
                  | none => True
                  | some minimum =>
                      time step.before + minimum <= deadline step.after node
                      /\ deadline step.after node <= time step.before + 2 * minimum)
            /\ (Not (ElectionReset step node)
                -> deadline step.after node = deadline step.before node)
            /\ (step.action = .local node (.timeout .election)
                -> deadline step.before node <= time step.before)

/-- A live node whose deadline has passed and which may start an election.
`startElection` runs only under `canStartElection`, so a node that cannot time
out is never due: only a halted clock could discharge its obligation. -/
def TimeoutDue (point : W) (node : NodeID) : Prop :=
  node ∈ live point
  /\ deadline point node <= time point
  /\ exists state,
      CCF.MultiNodeTransitionSystem.nodeState (proto point) node = some state
      /\ canStartElection state node

/-- A step that starts before the deadline of a live node that may start an
election ends at most `bound` past that deadline: the node is not paused for
longer than `bound` past its timeout. `none` allows any overshoot. -/
def NoOvershoot (bound : Option Real) (step : CCF.Execution.Step W Event) (node : NodeID)
    : Prop :=
  match bound with
  | none => True
  | some bound =>
      node ∈ live step.before
      -> (exists state,
            CCF.MultiNodeTransitionSystem.nodeState (proto step.before) node = some state
            /\ canStartElection state node)
      -> time step.before < deadline step.before node
      -> time step.after <= deadline step.before node + bound

/-- Valid election timeouts and progress.
`minimum = some delay` sets each reset's deadline between `delay` and `2 * delay`
later; `none` leaves the draw interval unconstrained.
Deadlines change only on resets, and timeouts cannot fire before them.
An eligible overdue node eventually times out or ceases
to be due even when `jitter = none`. With `jitter = some bound`, that obligation
resolves within `bound` of each recorded due state, and no step carries the clock
more than `bound` past an eligible node's deadline.
CCF checks on each `periodic` tick; zero jitter permits no delay once due and no
overshoot. Clock advancement remains in `timingModel`.
Needed (`NoOvershoot`): `Scheduled` counts only from the first recorded point at
which a node is due, so one idle step past every pending deadline would make
every node time out at once, whatever the draws. -/
structure ElectionScheduling (trace : Trace W Event) (minimum jitter : Option Real)
    : Prop where
  timeouts : ElectionTimeouts trace minimum
  firing
    : forall node,
        Scheduled trace jitter (fun point => TimeoutDue point node)
          (fun step => step.action = .local node (.timeout .election))
  noOvershoot
    : forall index step node,
        trace.stepAt index = some step -> NoOvershoot jitter step node

/-- The clock is unbounded along the recording: the execution neither stops nor
stalls. Needed: nothing else obliges a cluster without a primary to keep going. -/
def TimeDiverges (trace : Trace W Event) : Prop :=
  forall bound : Real,
    exists index point, trace.stateAt index = some point /\ bound <= time point

end CCFRaft.Liveness
