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

  class DeterministicScheduler
  {
  public:
    // One entry per point where the scheduler chose which ready actor
    // would run next: every actor that was ready at that point (with
    // whatever action label - see set_action() below - it had most
    // recently set for itself), and the index within that list of the one
    // actually chosen.
    struct Decision
    {
      std::vector<ActorId> ready;
      std::vector<std::string> ready_actions;
      size_t chosen_index;
    };

  private:
    struct MutexState
    {
      std::optional<ActorId> owner;
      std::vector<ActorId> waiters;
    };

    std::mutex m;
    std::condition_variable cv;
    size_t num_actors;
    size_t parked_count = 0;
    std::vector<bool> finished;
    std::vector<bool> blocked_on_lock;
    std::optional<ActorId> running;
    std::function<size_t(size_t num_ready)> chooser;
    std::vector<Decision> path;
    std::vector<std::string> actor_names;
    std::vector<std::string> current_action;

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
    // the real semantic label already reported via
    // ccf::pal::lock_label_sink/yield_point()'s own label - no further
    // production code changes needed) decide whether it actually
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
        if (!finished[a] && !blocked_on_lock[a])
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
      std::vector<std::string> ready_actions;
      ready_actions.reserve(ready.size());
      for (auto a : ready)
      {
        ready_actions.push_back(current_action[a]);
      }
      path.push_back(Decision{ready, std::move(ready_actions), chosen_index});
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
      finished(num_actors_, false),
      blocked_on_lock(num_actors_, false),
      chooser(std::move(chooser_)),
      actor_names(std::move(actor_names_)),
      // One extra slot beyond the real actors, for the reserved driver id
      // (see DriverRegistration) - the driver never contends for a lock or
      // gets scheduled, but can still call set_action() (transitively, via
      // ccf::pal::unique_lock's label reporting) while running application
      // code during make_run()/on_schedule().
      current_action(num_actors_ + 1)
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
    // as this actor's current action (as set_action() below would) before
    // the decision is made, so it appears in describe()'s output for this
    // decision point.
    void yield_point(ActorId self, std::string label = {})
    {
      std::unique_lock<std::mutex> lock(m);
      if (!label.empty())
      {
        current_action[self] = std::move(label);
      }
      choose_next(lock);
      cv.wait(lock, [&] { return running == self; });
    }

    // Records what this actor is currently doing (or about to do), purely
    // for describe() to report later - does not itself create a decision
    // point. Overwrites whatever this actor last set, and has no effect
    // once set until the next call (in particular, it is not cleared when
    // the actor finishes, so the last thing an actor did remains visible
    // in describe() for any later decision another actor triggers).
    void set_action(ActorId self, std::string label)
    {
      std::unique_lock<std::mutex> lock(m);
      current_action[self] = std::move(label);
    }

    // Called by SchedulerMutex::lock(). Blocks until this actor actually
    // holds the lock. Every acquisition is itself a decision point - once
    // this actor takes ownership (whether or not it had to wait for it),
    // the scheduler considers every ready actor, including this one
    // continuing immediately, before letting it proceed. The one
    // exception is the reserved driver "actor" (see DriverRegistration):
    // it never actually contends with a real actor for any lock, so its
    // own incidental lock use (e.g. real work done while constructing a
    // scenario's fixture) only needs to update ownership bookkeeping
    // consistently for whichever real actor looks at the same lock next -
    // not create a decision point of its own, since no other actor thread
    // even exists yet to be a candidate.
    void before_lock(ActorId self, void* mutex_key)
    {
      std::unique_lock<std::mutex> lock(m);
      auto& mtx = mutex_states[mutex_key];
      if (self >= num_actors)
      {
        mtx.owner = self;
        return;
      }
      while (mtx.owner.has_value())
      {
        mtx.waiters.push_back(self);
        blocked_on_lock[self] = true;
        choose_next(lock);
        cv.wait(lock, [&] { return running == self; });
        // Someone else may have taken it between this actor being woken
        // and it running again - the loop condition re-checks that.
      }
      mtx.owner = self;
      choose_next(lock);
      cv.wait(lock, [&] { return running == self; });
    }

    // Called by SchedulerMutex::unlock(), after releasing it. Every
    // release is itself a decision point, whether or not anything was
    // specifically waiting on this lock - any ready actor (including one
    // now free to claim this lock) is a candidate to run next. As in
    // before_lock() above, the reserved driver "actor" is the one
    // exception - it only needs to clear its own ownership bookkeeping.
    void after_unlock(ActorId self, void* mutex_key)
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
        blocked_on_lock[woken] = false;
      }
      choose_next(lock);
      cv.wait(lock, [&] { return running == self; });
    }

    // Called by an actor's thread once it has no more work to do.
    void finish(ActorId self)
    {
      std::unique_lock<std::mutex> lock(m);
      finished[self] = true;
      if (std::all_of(
            finished.begin(), finished.end(), [](bool f) { return f; }))
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

    // A human-readable rendering of decision_path(), one line per
    // decision: every actor that was ready at that point (name and
    // current action, if either was given), with the one chosen marked.
    // Intended for a failing test to attach to its own failure output
    // (e.g. via DOCTEST_INFO) - this scheduler has no opinion on when
    // that should happen.
    std::string describe() const
    {
      std::string out;
      for (size_t i = 0; i < path.size(); ++i)
      {
        const auto& decision = path[i];
        out += std::to_string(i) + ": ";
        for (size_t j = 0; j < decision.ready.size(); ++j)
        {
          if (j > 0)
          {
            out += ", ";
          }
          out += (j == decision.chosen_index ? "-> " : "   ");
          out += actor_label(decision.ready[j]);
          if (!decision.ready_actions[j].empty())
          {
            out += " (" + decision.ready_actions[j] + ")";
          }
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
  class SchedulerThreadContext
  {
    static thread_local DeterministicScheduler* current_scheduler;
    static thread_local ActorId current_actor;

  public:
    // Forwards ccf::pal::unique_lock's label reports (see
    // include/ccf/pal/locking.h) to whichever scheduler is active on the
    // calling thread (if any - a no-op otherwise), as with set_action()
    // below. Installed once, globally, by the static initializer below;
    // reads the calling thread's own current_scheduler/current_actor to
    // decide what to do, so does not itself need to be installed or
    // removed per-thread. Defined out-of-line, after ccf/pal/locking.h is
    // included below (see SchedulerMutex's own comment for why that must
    // come after this point in the file).
    static void forward_lock_label(const char* label);

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
  // thread. If `label` is non-empty, it is recorded as with set_action()
  // below before the decision is made.
  inline void yield_point(std::string label = {})
  {
    auto* scheduler = SchedulerThreadContext::scheduler();
    if (scheduler != nullptr)
    {
      scheduler->yield_point(SchedulerThreadContext::actor(), std::move(label));
    }
  }

  // Records what the calling actor is currently doing (or about to do),
  // purely so that DeterministicScheduler::describe() can report it
  // against whichever decision point comes next - see
  // DeterministicScheduler::set_action() for details. A no-op with no
  // scheduler active on the calling thread.
  inline void set_action(std::string label)
  {
    auto* scheduler = SchedulerThreadContext::scheduler();
    if (scheduler != nullptr)
    {
      scheduler->set_action(SchedulerThreadContext::actor(), std::move(label));
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

    void lock() CCF_ACQUIRE()
    {
      auto* scheduler = SchedulerThreadContext::scheduler();
      if (scheduler == nullptr)
      {
        mutex.lock();
        return;
      }
      scheduler->before_lock(SchedulerThreadContext::actor(), this);
    }

    void unlock() CCF_RELEASE()
    {
      auto* scheduler = SchedulerThreadContext::scheduler();
      if (scheduler == nullptr)
      {
        mutex.unlock();
        return;
      }
      scheduler->after_unlock(SchedulerThreadContext::actor(), this);
    }

    bool try_lock() CCF_TRY_ACQUIRE(true)
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
  inline void SchedulerThreadContext::forward_lock_label(const char* label)
  {
    if (current_scheduler != nullptr)
    {
      current_scheduler->set_action(current_actor, label);
    }
  }

  // Installs forward_lock_label() as ccf::pal::lock_label_sink exactly
  // once, for the lifetime of the process - not per-thread, since
  // forward_lock_label() already reads its own calling thread's
  // thread-local current_scheduler to no-op when that thread has none.
  namespace
  {
    struct LockLabelSinkInstaller
    {
      LockLabelSinkInstaller()
      {
        ccf::pal::lock_label_sink = &SchedulerThreadContext::forward_lock_label;
      }
    };
    const LockLabelSinkInstaller lock_label_sink_installer;
  }

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
