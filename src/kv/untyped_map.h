// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/dl_list.h"
#include "ds/logger.h"
#include "ds/spin_lock.h"
#include "kv/kv_serialiser.h"
#include "kv/kv_types.h"
#include "kv/untyped_tx_view.h"

#include <functional>
#include <optional>
#include <unordered_set>

namespace kv::untyped
{
  namespace Check
  {
    struct No
    {};

    template <typename T, typename Arg>
    No operator!=(const T&, const Arg&)
    {
      return No();
    }

    template <typename T, typename Arg = T>
    struct Ne
    {
      enum
      {
        value = !std::is_same<decltype(*(T*)(0) != *(Arg*)(0)), No>::value
      };
    };

    template <class T>
    bool ne(std::enable_if_t<Ne<T>::value, const T&> a, const T& b)
    {
      return a != b;
    }

    template <class T>
    bool ne(std::enable_if_t<!Ne<T>::value, const T&> a, const T& b)
    {
      return false;
    }
  }

  struct LocalCommit
  {
    LocalCommit() = default;
    LocalCommit(Version v, State&& s, const Write& w) :
      version(v),
      state(std::move(s)),
      writes(w)
    {}

    Version version;
    State state;
    Write writes;
    LocalCommit* next = nullptr;
    LocalCommit* prev = nullptr;
  };
  using LocalCommits = snmalloc::DLList<LocalCommit, std::nullptr_t, true>;

  struct Roll
  {
    std::unique_ptr<LocalCommits> commits;
    size_t rollback_counter;
  };

  class Map : public AbstractMap
  {
  public:
    using K = kv::serialisers::SerialisedEntry;
    using V = kv::serialisers::SerialisedEntry;
    using H = SerialisedKeyHasher;

    using CommitHook = CommitHook<Write>;

  private:
    AbstractStore* store;
    std::string name;
    Roll roll;
    CommitHook local_hook = nullptr;
    CommitHook global_hook = nullptr;
    std::list<std::pair<Version, Write>> commit_deltas;
    SpinLock sl;
    const SecurityDomain security_domain;
    const bool replicated;

    LocalCommits empty_commits;

    template <typename... Args>
    LocalCommit* create_new_local_commit(Args&&... args)
    {
      LocalCommit* c = empty_commits.pop();
      if (c == nullptr)
      {
        c = new LocalCommit(std::forward<Args>(args)...);
      }
      else
      {
        c->~LocalCommit();
        new (c) LocalCommit(std::forward<Args>(args)...);
      }
      return c;
    }

  public:
    class TxViewCommitter : public AbstractTxView
    {
    protected:
      ChangeSet change_set;

      Map& map;
      size_t rollback_counter;

      Version commit_version = NoVersion;

      bool changes = false;
      bool committed_writes = false;

    public:
      template <typename... Ts>
      TxViewCommitter(Map& m, size_t rollbacks, Ts&&... ts) :
        map(m),
        rollback_counter(rollbacks),
        change_set(std::forward<Ts>(ts)...)
      {}

      // Commit-related methods
      bool has_writes() override
      {
        return committed_writes || !change_set.writes.empty();
      }

      bool has_changes() override
      {
        return changes;
      }

      bool prepare() override
      {
        if (change_set.writes.empty())
          return true;

        auto& roll = map.get_roll();

        // If the parent map has rolled back since this transaction began, this
        // transaction must fail.
        if (rollback_counter != roll.rollback_counter)
          return false;

        // If we have iterated over the map, check for a global version match.
        auto current = roll.commits->get_tail();

        if (
          (change_set.read_version != NoVersion) &&
          (change_set.read_version != current->version))
        {
          LOG_DEBUG_FMT("Read version {} is invalid", change_set.read_version);
          return false;
        }

        // Check each key in our read set.
        for (auto it = change_set.reads.begin(); it != change_set.reads.end();
             ++it)
        {
          // Get the value from the current state.
          auto search = current->state.get(it->first);

          if (it->second == NoVersion)
          {
            // If we depend on the key not existing, it must be absent.
            if (search.has_value())
            {
              LOG_DEBUG_FMT("Read depends on non-existing entry");
              return false;
            }
          }
          else
          {
            // If we depend on the key existing, it must be present and have the
            // version that we expect.
            if (!search.has_value() || (it->second != search.value().version))
            {
              LOG_DEBUG_FMT("Read depends on invalid version of entry");
              return false;
            }
          }
        }

        return true;
      }

      void commit(Version v) override
      {
        if (change_set.writes.empty())
        {
          commit_version = change_set.start_version;
          return;
        }

        // Record our commit time.
        commit_version = v;
        committed_writes = true;

        if (!change_set.writes.empty())
        {
          auto& roll = map.get_roll();
          auto state = roll.commits->get_tail()->state;

          for (auto it = change_set.writes.begin();
               it != change_set.writes.end();
               ++it)
          {
            if (it->second.has_value())
            {
              // Write the new value with the global version.
              changes = true;
              state = state.put(it->first, VersionV{v, it->second.value()});
            }
            else
            {
              // Write an empty value with the deleted global version only if
              // the key exists.
              auto search = state.get(it->first);
              if (search.has_value())
              {
                changes = true;
                state = state.put(it->first, VersionV{-v, {}});
              }
            }
          }

          if (changes)
          {
            map.roll.commits->insert_back(map.create_new_local_commit(
              v, std::move(state), change_set.writes));
          }
        }
      }

      void post_commit() override
      {
        // This is run separately from commit so that all commits in the Tx
        // have been applied before local hooks are run. The maps in the Tx
        // are still locked when post_commit is run.
        if (change_set.writes.empty())
          return;

        map.trigger_local_hook();
      }

      // Used by owning map during serialise and deserialise
      ChangeSet& get_change_set()
      {
        return change_set;
      }

      const ChangeSet& get_change_set() const
      {
        return change_set;
      }

      void set_commit_version(Version v)
      {
        commit_version = v;
      }
    };

    struct ConcreteTxView : public TxViewCommitter, public TxView
    {
      ConcreteTxView(
        Map& m,
        size_t rollbacks,
        State& current_state,
        State& committed_state,
        Version v) :
        TxViewCommitter(m, rollbacks, current_state, committed_state, v),
        TxView(TxViewCommitter::change_set)
      {}
    };

    class Snapshot : public AbstractMap::Snapshot
    {
    private:
      std::string name;
      const SecurityDomain security_domain;
      const bool replicated;
      kv::Version version;
      champ::Snapshot<K, kv::untyped::VersionV, H> map_snapshot;

    public:
      Snapshot(
        std::string name_,
        SecurityDomain security_domain_,
        bool replicated_,
        kv::Version version_,
        champ::Snapshot<K, kv::untyped::VersionV, H>&& map_snapshot_) :
        name(name_),
        security_domain(security_domain_),
        replicated(replicated_),
        version(version_),
        map_snapshot(std::move(map_snapshot_))
      {}

      void serialize(uint8_t* data) override
      {
        map_snapshot.serialize(data);
      }

      size_t get_serialized_size() override
      {
        return map_snapshot.get_serialized_size();
      }

      const CBuffer& get_serialized_buffer() override
      {
        return map_snapshot.get_serialized_buffer();
      }

      std::string& get_name() override
      {
        return name;
      }

      SecurityDomain get_security_domain() override
      {
        return security_domain;
      }

      bool get_is_replicated() override
      {
        return replicated;
      }

      kv::Version get_version() override
      {
        return version;
      }
    };

    // Public typedef for external consumption
    using TxView = ConcreteTxView;

    Map(
      AbstractStore* store_,
      std::string name_,
      SecurityDomain security_domain_,
      bool replicated_) :
      store(store_),
      name(name_),
      roll{std::make_unique<LocalCommits>(), 0},
      security_domain(security_domain_),
      replicated(replicated_)
    {
      roll.commits->insert_back(create_new_local_commit(0, State(), Write()));
    }

    Map(const Map& that) = delete;

    virtual AbstractMap* clone(AbstractStore* other) override
    {
      return new Map(other, name, security_domain, replicated);
    }

    void serialise(
      const AbstractTxView* view,
      KvStoreSerialiser& s,
      bool include_reads) override
    {
      const auto committer = dynamic_cast<const TxViewCommitter*>(view);
      if (committer == nullptr)
      {
        LOG_FAIL_FMT("Unable to serialise map due to type mismatch");
        return;
      }

      const auto& change_set = committer->get_change_set();

      s.start_map(name, security_domain);

      if (include_reads)
      {
        s.serialise_read_version(change_set.read_version);

        s.serialise_count_header(change_set.reads.size());
        for (auto it = change_set.reads.begin(); it != change_set.reads.end();
             ++it)
        {
          s.serialise_read(it->first, it->second);
        }
      }
      else
      {
        s.serialise_read_version(NoVersion);
        s.serialise_count_header(0);
      }

      uint64_t write_ctr = 0;
      uint64_t remove_ctr = 0;
      for (auto it = change_set.writes.begin(); it != change_set.writes.end();
           ++it)
      {
        if (it->second.has_value())
        {
          ++write_ctr;
        }
        else
        {
          auto search = roll.commits->get_tail()->state.get(it->first);
          if (search.has_value())
          {
            ++remove_ctr;
          }
        }
      }

      s.serialise_count_header(write_ctr);
      for (auto it = change_set.writes.begin(); it != change_set.writes.end();
           ++it)
      {
        if (it->second.has_value())
        {
          s.serialise_write(it->first, it->second.value());
        }
      }

      s.serialise_count_header(remove_ctr);
      for (auto it = change_set.writes.begin(); it != change_set.writes.end();
           ++it)
      {
        if (!it->second.has_value())
        {
          s.serialise_remove(it->first);
        }
      }
    }

    AbstractTxView* deserialise(
      KvStoreDeserialiser& d, Version version) override
    {
      return deserialise_internal<TxView>(d, version);
    }

    template <typename TView>
    TView* deserialise_internal(KvStoreDeserialiser& d, Version version)
    {
      // Create a new change set, and deserialise d's contents into it.
      auto view = create_view<TView>(version);
      view->set_commit_version(version);

      auto& change_set = view->get_change_set();

      uint64_t ctr;

      auto rv = d.deserialise_read_version();
      if (rv != NoVersion)
      {
        change_set.read_version = rv;
      }

      ctr = d.deserialise_read_header();
      for (size_t i = 0; i < ctr; ++i)
      {
        auto r = d.deserialise_read();
        change_set.reads[std::get<0>(r)] = std::get<1>(r);
      }

      ctr = d.deserialise_write_header();
      for (size_t i = 0; i < ctr; ++i)
      {
        auto w = d.deserialise_write();
        change_set.writes[std::get<0>(w)] = std::get<1>(w);
      }

      ctr = d.deserialise_remove_header();
      for (size_t i = 0; i < ctr; ++i)
      {
        auto r = d.deserialise_remove();
        change_set.writes[r] = std::nullopt;
      }

      return view;
    }

    /** Get the name of the map
     *
     * @return const std::string&
     */
    const std::string& get_name() const override
    {
      return name;
    }

    /** Get store that the map belongs to
     *
     * @return Pointer to `kv::AbstractStore`
     */
    AbstractStore* get_store() override
    {
      return store;
    }

    /** Set handler to be called on local transaction commit
     *
     * @param hook function to be called on local transaction commit
     */
    void set_local_hook(const CommitHook& hook)
    {
      std::lock_guard<SpinLock> guard(sl);
      local_hook = hook;
    }

    /** Reset local transaction commit handler
     */
    void unset_local_hook()
    {
      std::lock_guard<SpinLock> guard(sl);
      local_hook = nullptr;
    }

    /** Set handler to be called on global transaction commit
     *
     * @param hook function to be called on global transaction commit
     */
    void set_global_hook(const CommitHook& hook)
    {
      std::lock_guard<SpinLock> guard(sl);
      global_hook = hook;
    }

    /** Reset global transaction commit handler
     */
    void unset_global_hook()
    {
      std::lock_guard<SpinLock> guard(sl);
      global_hook = nullptr;
    }

    /** Get security domain of a Map
     *
     * @return Security domain of the map (affects serialisation)
     */
    virtual SecurityDomain get_security_domain() override
    {
      return security_domain;
    }

    /** Get Map replicability
     *
     * @return true if the map is to be replicated, false if it is to be derived
     */
    virtual bool is_replicated() override
    {
      return replicated;
    }

    bool operator==(const AbstractMap& that) const override
    {
      auto p = dynamic_cast<const Map*>(&that);
      if (p == nullptr)
        return false;

      if (name != p->name)
        return false;

      auto state1 = roll.commits->get_tail();
      auto state2 = p->roll.commits->get_tail();

      if (state1->version != state2->version)
        return false;

      size_t count = 0;
      state2->state.foreach([&count](const K& k, const VersionV& v) {
        count++;
        return true;
      });

      size_t i = 0;
      bool ok =
        state1->state.foreach([&state2, &i](const K& k, const VersionV& v) {
          auto search = state2->state.get(k);

          if (search.has_value())
          {
            auto& found = search.value();
            if (found.version != v.version)
            {
              return false;
            }
            else if (Check::ne(found.value, v.value))
            {
              return false;
            }
          }
          else
          {
            return false;
          }

          i++;
          return true;
        });

      if (i != count)
        ok = false;

      return ok;
    }

    bool operator!=(const AbstractMap& that) const override
    {
      return !(*this == that);
    }

    std::unique_ptr<AbstractMap::Snapshot> snapshot(Version v) override
    {
      auto r = roll.commits->get_head();
      while (r != nullptr)
      {
        if (v < r->version)
        {
          break;
        }
        r = r->next;
      }

      if (r == nullptr)
      {
        r = roll.commits->get_tail();
      }
      else if (r->prev != nullptr)
      {
        r = r->prev;
      }

      champ::
        Snapshot<SerialisedEntry, kv::untyped::VersionV, SerialisedKeyHasher>
          snapshot(r->state);

      return std::move(std::make_unique<Snapshot>(
        name, security_domain, replicated, r->version, std::move(snapshot)));
    }

    void apply(std::unique_ptr<AbstractMap::Snapshot>& s) override
    {
      auto r = roll.commits->get_head();
      CCF_ASSERT(r != nullptr, "there must be at least 1 entry in the rolls");
      CCF_ASSERT(
        roll.commits->get_head() == roll.commits->get_tail(),
        "We are apply a snapshot and there are pending commits");

      const CBuffer& c = s->get_serialized_buffer();
      r->state = State::deserialize_map(c);
      r->version = s->get_version();
    }

    void compact(Version v) override
    {
      // This discards available rollback state before version v, and populates
      // the commit_deltas to be passed to the global commit hook, if there is
      // one, up to version v. The Map expects to be locked during compaction.
      while (roll.commits->get_head() != roll.commits->get_tail())
      {
        auto r = roll.commits->get_head();

        // Globally committed but not discardable.
        if (r->version == v)
        {
          // We know that write set is not empty.
          if (global_hook)
          {
            commit_deltas.emplace_back(r->version, std::move(r->writes));
          }
          return;
        }

        // Discardable, so move to commit_deltas.
        if (global_hook && !r->writes.empty())
        {
          commit_deltas.emplace_back(r->version, std::move(r->writes));
        }

        // Stop if the next state may be rolled back or is the only state.
        // This ensures there is always a state present.
        if (r->next->version > v)
          return;

        auto c = roll.commits->pop();
        empty_commits.insert(c);
      }

      // There is only one roll. We may need to call the commit hook.
      auto r = roll.commits->get_head();

      if (global_hook && !r->writes.empty())
      {
        commit_deltas.emplace_back(r->version, std::move(r->writes));
      }
    }

    void post_compact() override
    {
      if (global_hook)
      {
        for (auto& [version, writes] : commit_deltas)
        {
          global_hook(version, writes);
        }
      }

      commit_deltas.clear();
    }

    void rollback(Version v) override
    {
      // This rolls the current state back to version v.
      // The Map expects to be locked during rollback.
      bool advance = false;

      while (roll.commits->get_head() != roll.commits->get_tail())
      {
        auto r = roll.commits->get_tail();

        // The initial empty state has v = 0, so will not be discarded if it
        // is present.
        if (r->version <= v)
          break;

        advance = true;
        auto c = roll.commits->pop_tail();
        empty_commits.insert(c);
      }

      if (advance)
        roll.rollback_counter++;
    }

    void clear() override
    {
      // This discards all entries in the roll and resets the compacted value
      // and rollback counter. The Map expects to be locked before clearing it.
      roll.commits->clear();
      roll.commits->insert_back(create_new_local_commit(0, State(), Write()));
      roll.rollback_counter = 0;
    }

    void lock() override
    {
      sl.lock();
    }

    void unlock() override
    {
      sl.unlock();
    }

    void swap(AbstractMap* map_) override
    {
      Map* map = dynamic_cast<Map*>(map_);
      if (map == nullptr)
        throw std::logic_error(
          "Attempted to swap maps with incompatible types");

      std::swap(roll, map->roll);
    }

    template <typename TView>
    TView* create_view(Version version)
    {
      lock();

      // Find the last entry committed at or before this version.
      TView* view = nullptr;

      for (auto current = roll.commits->get_tail(); current != nullptr;
           current = current->prev)
      {
        if (current->version <= version)
        {
          view = new TView(
            *this,
            roll.rollback_counter,
            current->state,
            roll.commits->get_head()->state,
            current->version);
          break;
        }
      }

      if (view == nullptr)
      {
        view = new TView(
          *this,
          roll.rollback_counter,
          roll.commits->get_head()->state,
          roll.commits->get_head()->state,
          roll.commits->get_head()->version);
      }

      unlock();
      return view;
    }

    Roll& get_roll()
    {
      return roll;
    }

    void trigger_local_hook()
    {
      if (local_hook)
      {
        auto last_commit = roll.commits->get_tail();
        local_hook(last_commit->version, last_commit->writes);
      }
    }
  };
}