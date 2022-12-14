// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/logger.h"
#include "ccf/ds/mutex.h"
#include "ccf/kv/untyped_map_handle.h"
#include "ds/dl_list.h"
#include "kv/kv_serialiser.h"
#include "kv/kv_types.h"
#include "kv/untyped_change_set.h"

#include <functional>
#include <list>
#include <optional>
#include <unordered_set>

namespace kv::untyped
{
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

    LocalCommits empty_commits;

    void reset_commits()
    {
      commits->clear();
      commits->insert_back(create_new_local_commit(0, State(), Write()));
    }

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
  };

  class Map : public AbstractMap
  {
  public:
    using K = kv::untyped::SerialisedEntry;
    using V = kv::untyped::SerialisedEntry;
    using H = kv::untyped::SerialisedKeyHasher;

    using StateSnapshot = kv::untyped::State::Snapshot;

    using CommitHook = kv::untyped::CommitHook;
    using MapHook = kv::untyped::MapHook;

  private:
    AbstractStore* store;
    Roll roll;
    CommitHook global_hook = nullptr;
    MapHook hook = nullptr;
    std::list<std::pair<Version, Write>> commit_deltas;
    ccf::Mutex sl;
    const SecurityDomain security_domain;
    const bool replicated;
    const bool include_conflict_read_version;

  public:
    class HandleCommitter : public AbstractCommitter
    {
    protected:
      Map& map;

      ChangeSet& change_set;

      Version commit_version = NoVersion;

      bool changes = false;
      bool committed_writes = false;

    public:
      HandleCommitter(Map& m, ChangeSet& change_set_) :
        map(m),
        change_set(change_set_)
      {}

      // Commit-related methods
      bool has_writes() override
      {
        return committed_writes || change_set.has_writes();
      }

      bool prepare(bool track_read_versions) override
      {
        auto& roll = map.get_roll();

        // If the parent map has rolled back since this transaction began, this
        // transaction must fail.
        if (change_set.rollback_counter != roll.rollback_counter)
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

          if (std::get<0>(it->second) == NoVersion)
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
            // If the transaction depends on the key existing, it must be
            // present and have the the expected version. If also tracking
            // conflicts then ensure that the read versions also match.
            if (
              !search.has_value() ||
              std::get<0>(it->second) != search.value().version ||
              (track_read_versions &&
               std::get<1>(it->second) != search.value().read_version))
            {
              LOG_DEBUG_FMT("Read depends on invalid version of entry");
              return false;
            }
          }
        }

        return true;
      }

      void commit(Version v_, bool track_read_versions) override
      {
        if (change_set.writes.empty() && !track_read_versions)
        {
          commit_version = change_set.start_version;
          return;
        }

        auto& roll = map.get_roll();
        auto state = roll.commits->get_tail()->state;

        DeletableVersion v = static_cast<DeletableVersion>(v_);

        // To track conflicts the read version of all keys that are read or
        // written within a transaction must be updated.
        if (track_read_versions)
        {
          for (auto it = change_set.reads.begin(); it != change_set.reads.end();
               ++it)
          {
            auto search = state.get(it->first);
            if (!search.has_value())
            {
              continue;
            }
            state = state.put(
              it->first, VersionV{search->version, v_, search->value});
          }
          if (change_set.writes.empty())
          {
            commit_version = change_set.start_version;
            map.roll.commits->insert_back(map.roll.create_new_local_commit(
              commit_version, std::move(state), change_set.writes));
            return;
          }
        }

        // Record our commit time.
        commit_version = v;
        committed_writes = true;

        for (auto it = change_set.writes.begin(); it != change_set.writes.end();
             ++it)
        {
          if (it->second.has_value())
          {
            // Write the new value with the global version.
            changes = true;
            state = state.put(it->first, VersionV{v, v_, it->second.value()});
          }
          else
          {
            // Write an empty value with the deleted global version only if
            // the key exists.
            auto search = state.get(it->first);
            if (search.has_value())
            {
              changes = true;
              state = state.put(it->first, VersionV{-v, v_, {}});
            }
          }
        }

        if (changes)
        {
          map.roll.commits->insert_back(map.roll.create_new_local_commit(
            v, std::move(state), change_set.writes));
        }
      }

      ConsensusHookPtr post_commit() override
      {
        // This is run separately from commit so that all commits in the Tx
        // have been applied before map hooks are run. The maps in the Tx
        // are still locked when post_commit is run.
        return map.trigger_map_hook(commit_version, change_set.writes);
      }

      void set_commit_version(Version v)
      {
        commit_version = v;
      }
    };

    class Snapshot : public AbstractMap::Snapshot
    {
    private:
      const std::string name;
      const SecurityDomain security_domain;
      const kv::Version version;

      std::unique_ptr<StateSnapshot> map_snapshot;

    public:
      Snapshot(
        const std::string& name_,
        SecurityDomain security_domain_,
        kv::Version version_,
        std::unique_ptr<StateSnapshot>&& map_snapshot_) :
        name(name_),
        security_domain(security_domain_),
        version(version_),
        map_snapshot(std::move(map_snapshot_))
      {}

      void serialise(KvStoreSerialiser& s) override
      {
        LOG_TRACE_FMT("Serialising snapshot for map: {}", name);
        s.start_map(name, security_domain);
        s.serialise_entry_version(version);

        std::vector<uint8_t> ret(map_snapshot->get_serialized_size());
        map_snapshot->serialize(ret.data());
        s.serialise_raw(ret);
      }

      SecurityDomain get_security_domain() override
      {
        return security_domain;
      }
    };

    // Public typedefs for external consumption
    using ReadOnlyHandle = kv::untyped::MapHandle;
    using WriteOnlyHandle = kv::untyped::MapHandle;
    using Handle = kv::untyped::MapHandle;

    Map(
      AbstractStore* store_,
      const std::string& name_,
      SecurityDomain security_domain_,
      bool replicated_,
      bool include_conflict_read_version_) :
      AbstractMap(name_),
      store(store_),
      roll{std::make_unique<LocalCommits>(), 0, {}},
      security_domain(security_domain_),
      replicated(replicated_),
      include_conflict_read_version(include_conflict_read_version_)
    {
      roll.reset_commits();
    }

    Map(const Map& that) = delete;

    virtual AbstractMap* clone(AbstractStore* other) override
    {
      return new Map(
        other,
        name,
        security_domain,
        replicated,
        include_conflict_read_version);
    }

    void serialise_changes(
      const AbstractChangeSet* changes,
      KvStoreSerialiser& s,
      bool include_reads) override
    {
      const auto non_abstract =
        dynamic_cast<const kv::untyped::ChangeSet*>(changes);
      if (non_abstract == nullptr)
      {
        LOG_FAIL_FMT("Unable to serialise map due to type mismatch");
        return;
      }

      const auto& change_set = *non_abstract;

      s.start_map(name, security_domain);

      if (include_reads)
      {
        s.serialise_entry_version(change_set.read_version);

        s.serialise_count_header(change_set.reads.size());
        for (auto it = change_set.reads.begin(); it != change_set.reads.end();
             ++it)
        {
          s.serialise_read(it->first, std::get<0>(it->second));
        }
      }
      else
      {
        s.serialise_entry_version(NoVersion);
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
          ++remove_ctr;
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

    class SnapshotHandleCommitter : public AbstractCommitter
    {
    private:
      Map& map;

      SnapshotChangeSet& change_set;

    public:
      SnapshotHandleCommitter(Map& m, SnapshotChangeSet& change_set_) :
        map(m),
        change_set(change_set_)
      {}

      bool has_writes() override
      {
        return true;
      }

      bool prepare(bool) override
      {
        // Snapshots never conflict
        return true;
      }

      void commit(Version, bool) override
      {
        // Version argument is ignored. The version of the roll after the
        // snapshot is applied depends on the version of the map at which the
        // snapshot was taken.
        map.roll.reset_commits();
        map.roll.rollback_counter++;

        auto r = map.roll.commits->get_head();

        r->state = change_set.state;
        r->version = change_set.version;

        // Executing hooks from snapshot requires copying the entire snapshotted
        // state so only do it if there's a hook on the table
        if (map.hook || map.global_hook)
        {
          r->state.foreach([&r](const K& k, const VersionV& v) {
            if (is_deleted(v.version))
            {
              r->writes[k] = std::nullopt;
            }
            else
            {
              r->writes[k] = v.value;
            }
            return true;
          });
        }
      }

      ConsensusHookPtr post_commit() override
      {
        auto r = map.roll.commits->get_head();
        return map.trigger_map_hook(change_set.version, r->writes);
      }
    };

    ChangeSetPtr deserialise_snapshot_changes(KvStoreDeserialiser& d)
    {
      // Create a new empty change set, deserialising d's contents into it.
      auto v = d.deserialise_entry_version();
      auto map_snapshot = d.deserialise_raw();

      return std::make_unique<SnapshotChangeSet>(
        map::deserialize_map<State>(map_snapshot), v);
    }

    ChangeSetPtr deserialise_changes(KvStoreDeserialiser& d, Version version)
    {
      return deserialise_internal(d, version);
    }

    ChangeSetPtr deserialise_internal(KvStoreDeserialiser& d, Version version)
    {
      // Create a new change set, and deserialise d's contents into it.
      auto change_set_ptr = create_change_set(version);
      if (change_set_ptr == nullptr)
      {
        LOG_FAIL_FMT(
          "Failed to create change set over '{}' at {} - too early",
          name,
          version);
        throw std::logic_error("Can't create change set");
      }

      auto& change_set = *change_set_ptr;

      uint64_t ctr;

      auto rv = d.deserialise_entry_version();
      if (rv != NoVersion)
      {
        change_set.read_version = rv;
      }

      ctr = d.deserialise_read_header();
      for (size_t i = 0; i < ctr; ++i)
      {
        auto r = d.deserialise_read();
        change_set.reads[std::get<0>(r)] =
          std::make_tuple(std::get<1>(r), NoVersion);
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

      return change_set_ptr;
    }

    std::unique_ptr<AbstractCommitter> create_committer(
      AbstractChangeSet* changes) override
    {
      auto non_abstract = dynamic_cast<ChangeSet*>(changes);
      if (non_abstract == nullptr)
      {
        throw std::logic_error("Type confusion error");
      }

      auto snapshot_change_set = dynamic_cast<SnapshotChangeSet*>(non_abstract);
      if (snapshot_change_set != nullptr)
      {
        return std::make_unique<SnapshotHandleCommitter>(
          *this, *snapshot_change_set);
      }

      return std::make_unique<HandleCommitter>(*this, *non_abstract);
    }

    /** Get store that the map belongs to
     *
     * @return Pointer to `kv::AbstractStore`
     */
    AbstractStore* get_store() override
    {
      return store;
    }

    void set_map_hook(const MapHook& hook_)
    {
      hook = hook_;
    }

    void unset_map_hook()
    {
      hook = nullptr;
    }

    /** Set handler to be called on global transaction commit
     *
     * @param hook function to be called on global transaction commit
     */
    void set_global_hook(const CommitHook& hook)
    {
      global_hook = hook;
    }

    /** Reset global transaction commit handler
     */
    void unset_global_hook()
    {
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

    bool operator==(const Map& that) const
    {
      if (name != that.name)
        return false;

      auto state1 = roll.commits->get_tail();
      auto state2 = that.roll.commits->get_tail();

      if (state1->version != state2->version)
        return false;

      size_t count = 0;
      state2->state.foreach([&count](const K&, const VersionV&) {
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
            else if (found.value != v.value)
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

#ifndef __cpp_impl_three_way_comparison
    bool operator!=(const Map& that) const
    {
      return !(*this == that);
    }
#endif

    std::unique_ptr<AbstractMap::Snapshot> snapshot(Version v) override
    {
      // This takes a snapshot of the state of the map at the last entry
      // committed at or before this version. The Map expects to be locked while
      // taking the snapshot.
      auto r = roll.commits->get_head();

      for (auto current = roll.commits->get_tail(); current != nullptr;
           current = current->prev)
      {
        if (current->version <= v)
        {
          r = current;
          break;
        }
      }

      return std::make_unique<Snapshot>(
        name, security_domain, r->version, r->state.make_snapshot());
    }

    void compact(Version v) override
    {
      // This discards available rollback state before version v, and
      // populates the commit_deltas to be passed to the global commit hook,
      // if there is one, up to version v. The Map expects to be locked during
      // compaction.
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
        roll.empty_commits.insert(c);
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
        roll.empty_commits.insert(c);
      }

      if (advance)
        roll.rollback_counter++;
    }

    void clear() override
    {
      // This discards all entries in the roll and resets the rollback
      // counter. The Map expects to be locked before clearing it.
      roll.reset_commits();
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

    ChangeSetPtr create_change_set(Version version)
    {
      lock();

      ChangeSetPtr changes = nullptr;

      // Find the last entry committed at or before this version.
      for (auto current = roll.commits->get_tail(); current != nullptr;
           current = current->prev)
      {
        if (current->version <= version)
        {
          changes = std::make_unique<untyped::ChangeSet>(
            roll.rollback_counter,
            current->state,
            roll.commits->get_head()->state,
            current->version);
          break;
        }
      }

      // Returning nullptr is allowed, and indicates that we have no suitable
      // version - the version requested is _earlier_ than anything in the
      // roll

      unlock();
      return changes;
    }

    Roll& get_roll()
    {
      return roll;
    }

    ConsensusHookPtr trigger_map_hook(Version version, const Write& writes)
    {
      if (hook && !writes.empty())
      {
        return hook(version, writes);
      }
      return nullptr;
    }
  };
}