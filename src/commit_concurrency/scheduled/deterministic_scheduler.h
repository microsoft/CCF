// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

// A cooperative scheduler for deterministically exploring thread
// interleavings, plus SchedulerMutex, a lock type that reports its
// lock()/unlock() calls to whichever scheduler is active on the calling
// thread. Each participating actor runs on its own real OS thread, but the
// scheduler only ever lets one actor execute application code at a time;
// SchedulerMutex's lock()/unlock() calls are the points where it may hand
// control to a different actor instead of letting the caller continue.
//
// explore_all_interleavings() repeats a run once for every distinct
// sequence of such handoffs, via depth-first search with replay: each run
// records the choice made at every point where more than one actor was
// ready to proceed, and the next run replays the same choices up to the
// last such point and then tries the next untried alternative there.
// Every actor's work must therefore be reconstructed from scratch for each
// run (a fresh fixture, fresh threads) and depend on nothing outside what
// the scheduler controls, or two runs that replay the same prefix could
// diverge and make the recorded prefix meaningless.
//
// Exhaustive search does not scale to every scenario - estimate_schedule_
// count() gives a rough, cheap estimate of how many schedules a scenario
// would take to exhaust, before committing to running that many; once it
// is clearly too many, explore_random_interleavings() samples a chosen
// number of schedules at random instead, still fully reproducibly from a
// seed (exactly, unlike a real-thread fuzzer's timing-based randomness).
//
// A SchedulerMutex used with no scheduler active on the calling thread
// behaves like an ordinary mutex.

#include "ccf/ds/thread_safety.h"

#include <algorithm>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <random>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace ccf::pal
{
  // Forward declared so SchedulerMutex below can friend it - see
  // SchedulerMutex's own declaration for why. ccf/pal/locking.h is only
  // included (see below) once SchedulerMutex is a complete type - it may
  // become the definition of ccf::pal::Mutex itself for a whole build (see
  // CCF_TEST_INTERLEAVING_LOCK_TYPE there), which locking.h's own
  // MutexGuard and ConditionVariable need to be complete to compile
  // against.
  class ConditionVariable;
}

namespace ccf::kv::test
{
  using ActorId = size_t;

  // What an actor was last known to be doing, for describe() to report
  // against whichever decision comes next - whichever of these was
  // reported last for that actor, however many decisions ago, stays in
  // place until the next one (all three kinds behave identically here;
  // none is cleared automatically). Acquired/Released are recorded
  // automatically by before_lock()/after_unlock(), in sync with the exact
  // lock event that caused them - see SchedulerMutex's lock()/unlock().
  // YieldPoint is for a scenario's own yield_point() label, describing
  // something with no specific lock attached.
  enum class ActorEventKind
  {
    YieldPoint,
    Requested,
    Acquired,
    Released
  };

  struct ActorEvent
  {
    ActorEventKind kind = ActorEventKind::YieldPoint;
    std::string label;
  };

  class DeterministicScheduler
  {
  public:
    // One entry per point where the scheduler chose which ready actor
    // would run next. `trigger` is the actor whose own progress led here
    // (with `trigger_event`, the event it had just reported when it did)
    // - std::nullopt only for the very first decision (see kick_off()),
    // which has no preceding actor to attribute it to. Since only one
    // actor's code ever runs at a time, `trigger` is always exactly
    // whichever actor was `ready[chosen_index]` at the previous Decision.
    // `ready` and `chosen_index` are the full set of candidates the
    // scheduler picked from and which one it picked - not rendered by
    // describe() below, but load-bearing for explore_all_interleavings()'s
    // backtracking (see its own comments).
    struct Decision
    {
      std::optional<ActorId> trigger;
      ActorEvent trigger_event;
      std::vector<ActorId> ready;
      size_t chosen_index;
    };

  private:
    struct MutexState
    {
      std::optional<ActorId> owner;
      std::vector<ActorId> waiters;
    };

    // Per-actor state, indexed by ActorId - one entry per real actor,
    // plus one extra for the reserved driver id (see DriverRegistration):
    // the driver never gets marked finished or blocked_on_lock (its own
    // before_lock()/after_unlock() return early, before touching either),
    // but can still report a `current_event` via yield_point() while
    // registered.
    struct ActorState
    {
      bool finished = false;
      bool blocked_on_lock = false;
      ActorEvent current_event;
    };

    std::mutex m;
    std::condition_variable cv;
    size_t num_actors;
    size_t parked_count = 0;
    std::vector<ActorState> actors;
    std::optional<ActorId> running;
    std::function<size_t(size_t num_ready)> chooser;
    std::vector<Decision> path;
    std::vector<std::string> actor_names;

    // Falls back to "actor <n>" for any actor with no name given to the
    // constructor, or an empty name.
    std::string actor_label(ActorId a) const
    {
      if (a < actor_names.size() && !actor_names[a].empty())
      {
        return actor_names[a];
      }
      return "actor " + std::to_string(a);
    }

    // Must be called with m held. Picks the next actor to run by asking
    // `chooser` for an index into the ready set - the set of every actor
    // that is neither finished nor currently blocked waiting on a lock -
    // see the constructor's comment for what strategies that can be.
    //
    // TODO: every lock/unlock/yield_point() is currently an unconditional
    // decision point (branches the search over every ready actor). A
    // useful middle ground: treat each of these as only a *candidate*
    // decision point, and let a per-scenario predicate (matched against
    // the real ActorEvent already reported directly to before_lock()/
    // after_unlock()/yield_point() - no further production code changes
    // needed) decide whether it actually
    // branches, or just fast-passes the current actor through unchanged
    // (as the driver "actor" already does unconditionally below). Real
    // mutual exclusion is unaffected either way - only whether the search
    // explores alternatives there. This lets a scenario dial the search
    // space down to exactly the handful of points it cares about (e.g.
    // "the unlock of version_lock in Store::commit()"), rather than
    // choosing between "every lock branches" (often computationally
    // infeasible - see estimate_schedule_count()) and "only explicit
    // yield_points branch" (may miss semantic-lock-ordering bugs
    // entirely). Suggested workflow once this exists: random search over
    // the full, unfiltered space to find violations; turn each found
    // violation into a deterministic regression test pinned to its exact
    // decision sequence; then fuzz with a narrow allowlist around those
    // known points for cheap, targeted, ongoing coverage.
    void choose_next(std::unique_lock<std::mutex>& lock)
    {
      (void)lock;
      std::vector<ActorId> ready;
      for (ActorId a = 0; a < num_actors; ++a)
      {
        if (!actors[a].finished && !actors[a].blocked_on_lock)
        {
          ready.push_back(a);
        }
      }
      if (ready.empty())
      {
        throw std::logic_error(
          "DeterministicScheduler: every unfinished actor is blocked on a "
          "lock - deadlock");
      }

      const size_t chosen_index = chooser(ready.size());
      if (chosen_index >= ready.size())
      {
        throw std::logic_error(
          "DeterministicScheduler: chooser returned an out-of-range index "
          "- if replaying a recorded path, the scenario is not "
          "deterministic given the choices the scheduler controls");
      }
      // `running` still holds whichever actor was chosen at the previous
      // Decision (or nullopt, only for this very first one) - since only
      // one actor's code ever runs at a time, that is exactly the actor
      // whose own progress brought execution to this choose_next() call,
      // and actors[*running].current_event is exactly the event it just
      // reported to get here (see before_lock()/after_unlock()/
      // yield_point()'s own comments, all of which set their actor's
      // event immediately before calling this).
      const std::optional<ActorId> trigger = running;
      const ActorEvent trigger_event =
        trigger.has_value() ? actors[*trigger].current_event : ActorEvent{};
      path.push_back(Decision{trigger, trigger_event, ready, chosen_index});
      running = ready[chosen_index];
      cv.notify_all();
    }

  public:
    // `chooser_` is asked, at every decision point, to pick an index in
    // [0, num_ready) - the strategy that makes it e.g. depth-first search
    // with replay, or uniformly random, lives outside this class (see
    // explore_all_interleavings() and explore_random_interleavings()
    // below); DeterministicScheduler itself is agnostic to how choices are
    // made, only to enacting whichever one is made. `actor_names_`, if
    // given, is used by describe() below in place of "actor <n>" - it
    // need not name every actor, and is otherwise unused.
    DeterministicScheduler(
      size_t num_actors_,
      std::function<size_t(size_t num_ready)> chooser_,
      std::vector<std::string> actor_names_ = {}) :
      num_actors(num_actors_),
      // One extra slot beyond the real actors, for the reserved driver id
      // (see ActorState's own comment, and DriverRegistration).
      actors(num_actors_ + 1),
      chooser(std::move(chooser_)),
      actor_names(std::move(actor_names_))
    {}

    // Called by each actor's thread before it does any real work. Blocks
    // until every actor has reached this point, then further blocks until
    // this actor is the first one chosen to run.
    void wait_for_start(ActorId self)
    {
      std::unique_lock<std::mutex> lock(m);
      ++parked_count;
      cv.notify_all();
      cv.wait(lock, [&] { return running == self; });
    }

    // Called by the driver thread once every actor has been created, to
    // make the first scheduling decision. Blocks until all actors have
    // reached wait_for_start().
    void kick_off()
    {
      std::unique_lock<std::mutex> lock(m);
      cv.wait(lock, [&] { return parked_count == num_actors; });
      choose_next(lock);
    }

    // An explicit, always-branching decision point: every ready actor is a
    // candidate, regardless of what any of them are doing. Scenarios use
    // this (via the free function yield_point() below) to mark specific
    // points as worth exploring every interleaving of, independent of
    // whether a lock happens to be involved there - e.g. a gap between two
    // unrelated critical sections. Called with no scheduler active, it is
    // a no-op (see yield_point()). If `label` is non-empty, it is recorded
    // as this actor's current YieldPoint event before the decision is
    // made, so it appears in describe()'s output for this decision point.
    void yield_point(ActorId self, std::string label = {})
    {
      std::unique_lock<std::mutex> lock(m);
      if (!label.empty())
      {
        actors[self].current_event =
          ActorEvent{ActorEventKind::YieldPoint, std::move(label)};
      }
      choose_next(lock);
      cv.wait(lock, [&] { return running == self; });
    }

    // Called by SchedulerMutex::lock(). Blocks until this actor actually
    // holds the lock. The attempt itself is a decision point (its
    // Requested event, below), before even checking whether the lock is
    // free - without this, whichever actor happened to be running when
    // it reached an uncontended lock would always win it unconditionally,
    // since (only one actor's code ever runs at a time) no other actor
    // could otherwise ever get a chance to reach for the same lock first.
    // Acquiring it (whether or not this actor had to wait first) is a
    // further decision point of its own, with an Acquired event. `label`
    // (if given - see ccf::pal::unique_lock, the only real caller that
    // supplies one) is used for both events. The one exception is the
    // reserved driver "actor" (see DriverRegistration): it never actually
    // contends with a real actor for any lock, so its own incidental lock
    // use (e.g. real work done while constructing a scenario's fixture)
    // only needs to update ownership bookkeeping consistently for
    // whichever real actor looks at the same lock next - not create any
    // decision point, or event, of its own, since no other actor thread
    // even exists yet to be a candidate.
    void before_lock(ActorId self, void* mutex_key, const char* label = nullptr)
    {
      std::unique_lock<std::mutex> lock(m);
      auto& mtx = mutex_states[mutex_key];
      if (self >= num_actors)
      {
        mtx.owner = self;
        return;
      }
      actors[self].current_event =
        ActorEvent{ActorEventKind::Requested, label != nullptr ? label : ""};
      choose_next(lock);
      cv.wait(lock, [&] { return running == self; });

      while (mtx.owner.has_value())
      {
        mtx.waiters.push_back(self);
        actors[self].blocked_on_lock = true;
        choose_next(lock);
        cv.wait(lock, [&] { return running == self; });
        // Someone else may have taken it between this actor being woken
        // and it running again - the loop condition re-checks that.
      }
      mtx.owner = self;
      actors[self].current_event =
        ActorEvent{ActorEventKind::Acquired, label != nullptr ? label : ""};
      choose_next(lock);
      cv.wait(lock, [&] { return running == self; });
    }

    // Called by SchedulerMutex::unlock(), after releasing it. Every
    // release is itself a decision point, whether or not anything was
    // specifically waiting on this lock - any ready actor (including one
    // now free to claim this lock) is a candidate to run next. `label`
    // becomes this actor's Released event, recorded right before that
    // same decision, so it is visible from this decision onward. As in
    // before_lock() above, the reserved driver "actor" is the one
    // exception - it only needs to clear its own ownership bookkeeping.
    void after_unlock(
      ActorId self, void* mutex_key, const char* label = nullptr)
    {
      std::unique_lock<std::mutex> lock(m);
      auto& mtx = mutex_states[mutex_key];
      mtx.owner.reset();
      if (self >= num_actors)
      {
        return;
      }
      if (!mtx.waiters.empty())
      {
        const auto woken = mtx.waiters.front();
        mtx.waiters.erase(mtx.waiters.begin());
        actors[woken].blocked_on_lock = false;
      }
      actors[self].current_event =
        ActorEvent{ActorEventKind::Released, label != nullptr ? label : ""};
      choose_next(lock);
      cv.wait(lock, [&] { return running == self; });
    }

    // Called by an actor's thread once it has no more work to do.
    void finish(ActorId self)
    {
      std::unique_lock<std::mutex> lock(m);
      actors[self].finished = true;
      // Only the real actors (not the reserved driver slot, which is
      // never marked finished) need to have finished.
      if (std::all_of(
            actors.begin(),
            actors.begin() + static_cast<ptrdiff_t>(num_actors),
            [](const ActorState& a) { return a.finished; }))
      {
        running.reset();
        cv.notify_all();
        return;
      }
      choose_next(lock);
    }

    const std::vector<Decision>& decision_path() const
    {
      return path;
    }

    // A human-readable event stream, one line per decision: what the
    // triggering actor (see Decision's own comment) just did, and - only
    // when a genuine handoff happens, i.e. a different actor is chosen
    // to continue - which actor resumes next. Deliberately does not list
    // every other actor that was merely ready at that point (blocked or
    // idly-ready-but-not-chosen are not a meaningful distinction here);
    // decision_path() above still has that, for anything that needs it
    // (e.g. explore_all_interleavings()'s own backtracking). Intended for
    // a failing test to attach to its own failure output (e.g. via
    // DOCTEST_INFO) - this scheduler has no opinion on when that should
    // happen.
    std::string describe() const
    {
      std::string out;
      for (size_t i = 0; i < path.size(); ++i)
      {
        const auto& decision = path[i];
        out += std::to_string(i) + ": ";
        if (decision.trigger.has_value())
        {
          out += actor_label(*decision.trigger);
          const auto& event = decision.trigger_event;
          if (!event.label.empty())
          {
            switch (event.kind)
            {
              case ActorEventKind::Requested:
                out += " requests " + event.label;
                break;
              case ActorEventKind::Acquired:
                out += " acquires " + event.label;
                break;
              case ActorEventKind::Released:
                out += " releases " + event.label;
                break;
              case ActorEventKind::YieldPoint:
              default:
                out += ": " + event.label;
                break;
            }
          }
          const auto chosen = decision.ready[decision.chosen_index];
          if (chosen != *decision.trigger)
          {
            out += ", " + actor_label(chosen) + " resumes";
          }
        }
        else
        {
          // The very first decision (see kick_off()) - nobody's own
          // progress caused this one, it is simply who runs first.
          out += actor_label(decision.ready[decision.chosen_index]) + " starts";
        }
        out += "\n";
      }
      return out;
    }

  private:
    // Keyed by SchedulerMutex identity (its `this` pointer) rather than
    // held inside SchedulerMutex itself, so SchedulerMutex stays a plain,
    // cheap, default-constructible value with no dependency on whichever
    // scheduler (if any) ends up using it.
    std::unordered_map<void*, MutexState> mutex_states;
  };

  // Finds, and points a thread at, whichever DeterministicScheduler (if
  // any) is exploring interleavings on the calling thread.
  // Finds, and points a thread at, whichever DeterministicScheduler (if
  // any) is exploring interleavings on the calling thread.
  class SchedulerThreadContext
  {
    static thread_local DeterministicScheduler* current_scheduler;
    static thread_local ActorId current_actor;

  public:
    static void set(DeterministicScheduler* scheduler, ActorId actor)
    {
      current_scheduler = scheduler;
      current_actor = actor;
    }

    static void clear()
    {
      current_scheduler = nullptr;
    }

    static DeterministicScheduler* scheduler()
    {
      return current_scheduler;
    }

    static ActorId actor()
    {
      return current_actor;
    }
  };

  inline thread_local DeterministicScheduler*
    SchedulerThreadContext::current_scheduler = nullptr;
  inline thread_local ActorId SchedulerThreadContext::current_actor = 0;

  // An explicit point for explore_all_interleavings() to consider every
  // ready actor as a candidate to run next, independent of any lock -
  // e.g. a gap between two unrelated critical sections that a scenario
  // wants every interleaving of, not just the ones lock contention alone
  // would produce. A no-op with no scheduler active on the calling
  // thread. If `label` is non-empty, it is recorded as this actor's
  // current YieldPoint event before the decision is made.
  inline void yield_point(std::string label = {})
  {
    auto* scheduler = SchedulerThreadContext::scheduler();
    if (scheduler != nullptr)
    {
      scheduler->yield_point(SchedulerThreadContext::actor(), std::move(label));
    }
  }

  // A BasicLockable/Lockable type, suitable everywhere ccf::pal::Mutex is
  // (std::lock_guard, std::unique_lock, std::scoped_lock all accept any
  // type with these three members). With no DeterministicScheduler active
  // on the calling thread, this behaves like an ordinary mutex; the
  // scheduler-driven behaviour above only applies inside a run started via
  // explore_all_interleavings() (or DeterministicScheduler used directly).
  //
  // Carries the same Clang thread-safety annotations as ccf::pal::Mutex,
  // and the same private member name `mutex` (friended to
  // ccf::pal::ConditionVariable, exactly as ccf::pal::Mutex friends it), so
  // that this can stand in for ccf::pal::Mutex itself for a whole build
  // (see CCF_TEST_INTERLEAVING_LOCK_TYPE in include/ccf/pal/locking.h) -
  // including code that only compiles ccf::pal::ConditionVariable::wait()
  // and friends without ever actually executing them at runtime.
  class CCF_CAPABILITY("mutex") SchedulerMutex
  {
    friend class ccf::pal::ConditionVariable;
    std::mutex mutex;

  public:
    using native_handle_type = std::mutex::native_handle_type;

    SchedulerMutex() = default;
    SchedulerMutex(const SchedulerMutex&) = delete;
    SchedulerMutex& operator=(const SchedulerMutex&) = delete;

    // `label`, if given, is passed straight through to before_lock() -
    // see ccf::pal::unique_lock, the only real caller that supplies one.
    void lock(const char* label = nullptr) CCF_ACQUIRE()
    {
      auto* scheduler = SchedulerThreadContext::scheduler();
      if (scheduler == nullptr)
      {
        mutex.lock();
        return;
      }
      scheduler->before_lock(SchedulerThreadContext::actor(), this, label);
    }

    // `label`, if given, is passed straight through to after_unlock().
    void unlock(const char* label = nullptr) CCF_RELEASE()
    {
      auto* scheduler = SchedulerThreadContext::scheduler();
      if (scheduler == nullptr)
      {
        mutex.unlock();
        return;
      }
      scheduler->after_unlock(SchedulerThreadContext::actor(), this, label);
    }

    bool try_lock(const char* label = nullptr) CCF_TRY_ACQUIRE(true)
    {
      auto* scheduler = SchedulerThreadContext::scheduler();
      if (scheduler == nullptr)
      {
        return mutex.try_lock();
      }
      // Not part of any of the scenarios this rig currently drives -
      // implement only once a scenario actually needs it, so that its
      // scheduling semantics can be designed against a real use rather
      // than guessed at.
      (void)label;
      throw std::logic_error(
        "SchedulerMutex::try_lock() is not implemented under an active "
        "DeterministicScheduler");
    }

    native_handle_type native_handle()
    {
      return mutex.native_handle();
    }
  };
}

// Only included here, rather than at the top of this file, because
// ccf/pal/locking.h may make ccf::pal::Mutex itself an alias for
// SchedulerMutex above (see CCF_TEST_INTERLEAVING_LOCK_TYPE there) - its
// own MutexGuard and ConditionVariable need SchedulerMutex to already be a
// complete type to compile against it.
#include "ccf/pal/locking.h"

namespace ccf::kv::test
{
  // Registers/unregisters the calling (driver) thread with `scheduler` as
  // a reserved actor id (one beyond the real actors, so it never collides
  // with one), so that any SchedulerMutex it locks - during make_run() or
  // on_schedule(), the only places the driver thread runs application code
  // - goes through the same scheduler bookkeeping a real actor's would,
  // rather than falling back to real locking. This driver "actor" never
  // actually contends with a real actor for any lock: make_run() runs
  // strictly before any actor thread starts, and on_schedule() strictly
  // after every actor thread has finished and been joined.
  class DriverRegistration
  {
    DeterministicScheduler& scheduler;
    ActorId id;
    bool registered = false;

  public:
    DriverRegistration(DeterministicScheduler& scheduler_, ActorId id_) :
      scheduler(scheduler_),
      id(id_)
    {
      set();
    }

    ~DriverRegistration()
    {
      clear();
    }

    void set()
    {
      if (!registered)
      {
        SchedulerThreadContext::set(&scheduler, id);
        registered = true;
      }
    }

    void clear()
    {
      if (registered)
      {
        SchedulerThreadContext::clear();
        registered = false;
      }
    }

    DriverRegistration(const DriverRegistration&) = delete;
    DriverRegistration& operator=(const DriverRegistration&) = delete;
  };

  // Runs `make_run` once per explored schedule. `make_run` must construct
  // whatever fresh state the scenario needs (e.g. a fixture) and return
  // exactly `num_actors` callables - the body to run, on its own thread,
  // for each actor in that particular run. Every callable must call
  // ccf::kv::test::SchedulerThreadContext::set() first if it wants that
  // thread's SchedulerMutex use to be scheduled (any thread that never
  // calls it behaves as if no scheduler were active at all).
  //
  // If given, `on_schedule` is called after every schedule's actors have
  // all finished, before the state made by that schedule's `make_run` call
  // is discarded - the place to check per-schedule invariants or tally
  // outcomes across schedules. It is passed the scheduler itself, so it
  // can call scheduler.describe() (typically attached via DOCTEST_INFO)
  // to explain what happened on that schedule if it goes on to report a
  // failure.
  //
  // `actor_names`, if given, labels each actor in scheduler.describe()'s
  // output in place of "actor <n>" - see DeterministicScheduler's
  // constructor.
  //
  // Explores schedules via depth-first search with replay (see file
  // comment above) until every alternative at every decision point has
  // been tried, or `max_schedules` is reached first - a circuit breaker
  // against scenarios whose interleaving space is too large to exhaust in
  // practice, so a mistakenly-unbounded scenario fails loudly rather than
  // running forever. Use estimate_schedule_count() below to get a rough
  // idea of how large that space is before committing to an exhaustive
  // search. Returns the number of schedules explored.
  inline size_t explore_all_interleavings(
    size_t num_actors,
    const std::function<std::vector<std::function<void()>>()>& make_run,
    const std::function<void(const DeterministicScheduler&)>& on_schedule = {},
    size_t max_schedules = 100000,
    std::vector<std::string> actor_names = {})
  {
    // Replays `prefix` (the choices made at each decision point up to and
    // including the last one backtracked to), then defaults to the
    // left-most alternative for every decision point beyond that -
    // exactly depth-first search with replay.
    struct PrefixThenLeftmostChooser
    {
      std::vector<size_t> prefix;
      size_t pos = 0;

      size_t operator()(size_t num_ready)
      {
        const size_t chosen = pos < prefix.size() ? prefix[pos] : 0;
        ++pos;
        return chosen < num_ready ? chosen : num_ready;
      }
    };

    std::vector<size_t> prefix;
    size_t schedules_explored = 0;

    for (;;)
    {
      if (schedules_explored >= max_schedules)
      {
        throw std::logic_error(
          "explore_all_interleavings: max_schedules reached without "
          "exhausting every interleaving - scope the scenario down, or "
          "raise the limit if this many schedules is genuinely expected");
      }

      DeterministicScheduler scheduler(
        num_actors, PrefixThenLeftmostChooser{prefix, 0}, actor_names);

      // make_run() (constructing whatever fixture the scenario needs) runs
      // here, on this driver thread, before any actor thread exists - so
      // it is registered with this schedule's scheduler too (as actor id
      // num_actors, never used by any real actor), rather than left
      // unregistered. This matters whenever a SchedulerMutex reachable
      // from make_run() is shared with something outside this scenario's
      // own fixture (e.g. a process-wide singleton) - an unregistered
      // thread takes such a lock for real, while a registered one only
      // does scheduler bookkeeping; consistently registering every thread
      // that can reach such a lock avoids that mismatch. Safe because
      // this driver "actor" is never actually contended for by a real
      // actor - it only ever touches such locks strictly before any actor
      // starts, or strictly after every actor has finished (see below).
      DriverRegistration driver_registration(scheduler, num_actors);
      auto bodies = make_run();
      if (bodies.size() != num_actors)
      {
        throw std::logic_error(
          "explore_all_interleavings: make_run() did not return one body "
          "per actor");
      }
      driver_registration.clear();

      std::vector<std::thread> threads;
      threads.reserve(num_actors);
      for (ActorId a = 0; a < num_actors; ++a)
      {
        threads.emplace_back([&scheduler, &bodies, a]() {
          SchedulerThreadContext::set(&scheduler, a);
          scheduler.wait_for_start(a);
          bodies[a]();
          scheduler.finish(a);
          SchedulerThreadContext::clear();
        });
      }
      scheduler.kick_off();
      for (auto& t : threads)
      {
        t.join();
      }
      ++schedules_explored;
      if (on_schedule)
      {
        driver_registration.set();
        on_schedule(scheduler);
        driver_registration.clear();
      }

      // Backtrack: find the last decision with an untried alternative,
      // and set the prefix to replay everything up to and including it,
      // advanced to the next alternative there.
      const auto& path = scheduler.decision_path();
      std::optional<size_t> backtrack_at;
      for (size_t i = path.size(); i-- > 0;)
      {
        if (path[i].chosen_index + 1 < path[i].ready.size())
        {
          backtrack_at = i;
          break;
        }
      }
      if (!backtrack_at.has_value())
      {
        // Every decision, at every depth, chose its last alternative:
        // nothing left to explore.
        return schedules_explored;
      }

      prefix.clear();
      prefix.reserve(*backtrack_at + 1);
      for (size_t i = 0; i < *backtrack_at; ++i)
      {
        prefix.push_back(path[i].chosen_index);
      }
      prefix.push_back(path[*backtrack_at].chosen_index + 1);
    }
  }

  // Runs `make_run` once per sample, choosing uniformly at random (seeded
  // by `seed`, so the whole sequence of samples is reproducible) at every
  // decision point instead of exhaustively searching every alternative.
  // Useful once estimate_schedule_count() below shows the full space is
  // too large to exhaust in practice, but a scenario is still worth
  // sampling for interleavings a purely timing-based fuzzer might miss.
  // `make_run`, `on_schedule`, and `actor_names` behave exactly as in
  // explore_all_interleavings().
  inline void explore_random_interleavings(
    size_t num_actors,
    const std::function<std::vector<std::function<void()>>()>& make_run,
    const std::function<void(const DeterministicScheduler&)>& on_schedule,
    size_t num_samples,
    uint32_t seed,
    std::vector<std::string> actor_names = {})
  {
    struct RandomChooser
    {
      std::mt19937 rng;

      size_t operator()(size_t num_ready)
      {
        return std::uniform_int_distribution<size_t>(0, num_ready - 1)(rng);
      }
    };

    std::mt19937 seed_rng(seed);
    for (size_t sample = 0; sample < num_samples; ++sample)
    {
      DeterministicScheduler scheduler(
        num_actors, RandomChooser{std::mt19937(seed_rng())}, actor_names);
      DriverRegistration driver_registration(scheduler, num_actors);
      auto bodies = make_run();
      if (bodies.size() != num_actors)
      {
        throw std::logic_error(
          "explore_random_interleavings: make_run() did not return one "
          "body per actor");
      }
      driver_registration.clear();

      std::vector<std::thread> threads;
      threads.reserve(num_actors);
      for (ActorId a = 0; a < num_actors; ++a)
      {
        threads.emplace_back([&scheduler, &bodies, a]() {
          SchedulerThreadContext::set(&scheduler, a);
          scheduler.wait_for_start(a);
          bodies[a]();
          scheduler.finish(a);
          SchedulerThreadContext::clear();
        });
      }
      scheduler.kick_off();
      for (auto& t : threads)
      {
        t.join();
      }
      if (on_schedule)
      {
        driver_registration.set();
        on_schedule(scheduler);
        driver_registration.clear();
      }
    }
  }

  // A rough estimate of how many schedules explore_all_interleavings()
  // would need to exhaust the full interleaving space of this scenario,
  // without actually exhausting it: `num_walks` independent random walks
  // down the decision tree, each multiplying together the number of ready
  // candidates at every decision point it passes through (an unbiased
  // estimator of the tree's total leaf count - the same technique used to
  // estimate game tree sizes without expanding them in full). A single
  // walk has high variance, so this returns every walk's estimate rather
  // than just one number - look at the spread (e.g. min/max, or a
  // geometric mean) rather than trusting any individual value, and treat
  // the result as an order of magnitude, not a precise count.
  inline std::vector<double> estimate_schedule_count(
    size_t num_actors,
    const std::function<std::vector<std::function<void()>>()>& make_run,
    size_t num_walks = 30,
    uint32_t seed = 1)
  {
    struct EstimatingRandomChooser
    {
      std::mt19937 rng;
      double* product;

      size_t operator()(size_t num_ready)
      {
        *product *= static_cast<double>(num_ready);
        return std::uniform_int_distribution<size_t>(0, num_ready - 1)(rng);
      }
    };

    std::vector<double> estimates;
    estimates.reserve(num_walks);
    std::mt19937 seed_rng(seed);

    for (size_t walk = 0; walk < num_walks; ++walk)
    {
      double product = 1.0;
      DeterministicScheduler scheduler(
        num_actors,
        EstimatingRandomChooser{std::mt19937(seed_rng()), &product});
      DriverRegistration driver_registration(scheduler, num_actors);
      auto bodies = make_run();
      if (bodies.size() != num_actors)
      {
        throw std::logic_error(
          "estimate_schedule_count: make_run() did not return one body "
          "per actor");
      }
      driver_registration.clear();

      std::vector<std::thread> threads;
      threads.reserve(num_actors);
      for (ActorId a = 0; a < num_actors; ++a)
      {
        threads.emplace_back([&scheduler, &bodies, a]() {
          SchedulerThreadContext::set(&scheduler, a);
          scheduler.wait_for_start(a);
          bodies[a]();
          scheduler.finish(a);
          SchedulerThreadContext::clear();
        });
      }
      scheduler.kick_off();
      for (auto& t : threads)
      {
        t.join();
      }
      estimates.push_back(product);
    }
    return estimates;
  }
}
