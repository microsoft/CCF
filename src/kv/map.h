// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/champ_map.h"
#include "ds/dl_list.h"
#include "ds/logger.h"
#include "ds/spin_lock.h"
#include "kv_serialiser.h"
#include "kv_types.h"

#include <functional>
#include <optional>
#include <unordered_map>
#include <unordered_set>

namespace kv
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

  template <typename V>
  struct VersionV
  {
    Version version;
    V value;

    VersionV() = default;
    VersionV(Version ver, V val) : version(ver), value(val) {}
  };

  template <typename K, typename V, typename H>
  using State = champ::Map<K, VersionV<V>, H>;

  template <typename K, typename V, typename H>
  using Read = std::unordered_map<K, Version, H>;

  template <typename K, typename V, typename H>
  using Write = std::unordered_map<K, VersionV<V>, H>;

  /// Signature for transaction commit handlers
  template <typename K, typename V, typename H>
  using CommitHook =
    std::function<void(Version, const State<K, V, H>&, const Write<K, V, H>&)>;

  template <typename K, typename V, typename H>
  class StateAccessor
  {
  protected:
    using VersionV = VersionV<V>;
    using State = State<K, V, H>;
    using Read = Read<K, V, H>;
    using Write = Write<K, V, H>;

    State state;
    State committed;
    Version start_version;

    Read reads = {};
    Write writes = {};
    Version read_version = NoVersion;

  public:
    StateAccessor(State& current_state, State& committed_state, Version v) :
      state(current_state),
      committed(committed_state),
      start_version(v)
    {}

    /** Get value for key
     *
     * This returns the value for the key inside the transaction. If the key
     * has been updated in the current transaction, that update will be
     * reflected in the return of this call.
     *
     * @param key Key
     *
     * @return optional containing value, empty if the key doesn't exist
     */
    std::optional<V> get(const K& key)
    {
      // A write followed by a read doesn't introduce a read dependency.
      // If we have written, return the value without updating the read set.
      auto write = writes.find(key);
      if (write != writes.end())
      {
        // Return empty for a key that has been removed.
        if (deleted(write->second.version))
        {
          return std::nullopt;
        }

        return write->second.value;
      }

      // If the key doesn't exist, return empty and record that we depend on
      // the key not existing.
      auto search = state.get(key);
      if (!search.has_value())
      {
        reads.insert(std::make_pair(key, NoVersion));
        return std::nullopt;
      }

      // Record the version that we depend on.
      auto& found = search.value();
      reads.insert(std::make_pair(key, found.version));

      // If the key has been deleted, return empty.
      if (deleted(found.version))
      {
        return std::nullopt;
      }

      // Return the value.
      return found.value;
    }

    /** Get globally committed value for key
     *
     * This reads a globally replicated value for the specified key.
     * The value will have been the replicated value when the transaction
     * began, but the map may be compacted while the transaction is in
     * flight. If that happens, there may be a more recent committed
     * version. This is undetectable to the transaction.
     *
     * @param key Key
     *
     * @return optional containing value, empty if the key doesn't exist in
     * globally committed state
     */
    std::optional<V> get_globally_committed(const K& key)
    {
      // If there is no committed value, return empty.
      auto search = committed.get(key);
      if (!search.has_value())
      {
        return std::nullopt;
      }

      // If the key has been deleted, return empty.
      auto& found = search.value();
      if (deleted(found.version))
      {
        return std::nullopt;
      }

      // Return the value.
      return found.value;
    }

    /** Write value at key
     *
     * If the key already exists, the value will be replaced.
     * This will fail if the transaction is already committed.
     *
     * @param key Key
     * @param value Value
     *
     * @return true if successful, false otherwise
     */
    bool put(const K& key, const V& value)
    {
      // Record in the write set.
      writes[key] = {0, value};
      return true;
    }

    /** Remove key
     *
     * This will fail if the key does not exist, or if the transaction
     * is already committed.
     *
     * @param key Key
     *
     * @return true if successful, false otherwise
     */
    bool remove(const K& key)
    {
      auto write = writes.find(key);
      auto search = state.get(key).has_value();

      if (write != writes.end())
      {
        if (!search)
        {
          // this key only exists locally, there is no reason to maintain and
          // serialise it
          writes.erase(key);
        }
        else
        {
          // If we have written, change the write set to indicate a remove.
          write->second = {NoVersion, V()};
        }

        return true;
      }

      // If the key doesn't exist, return false.
      if (!search)
      {
        return false;
      }

      // Record in the write set.
      writes.emplace(
        std::piecewise_construct,
        std::forward_as_tuple(key),
        std::forward_as_tuple(NoVersion, V()));
      return true;
    }

    /** Iterate over all entries in the map
     *
     * @param F functor, taking a key and a value, return value determines
     * whether the iteration should continue (true) or stop (false)
     */
    template <class F>
    bool foreach(F&& f)
    {
      // Record a global read dependency.
      read_version = start_version;
      auto& w = writes;

      state.foreach([&w, &f](const K& k, const VersionV& v) {
        auto write = w.find(k);

        if ((write == w.end()) && !deleted(v.version))
          return f(k, v.value);
        return true;
      });

      for (auto write = writes.begin(); write != writes.end(); ++write)
      {
        if (!deleted(write->second.version))
          if (!f(write->first, write->second.value))
            return false;
      }
      return true;
    }
  };

  template <class K, class V, class H = std::hash<K>>
  class Map;

  template <class K, class V, class H>
  class CommittableStateAccessor : public StateAccessor<K, V, H>
  {
  protected:
    using Base = StateAccessor<K, V, H>;
    using MyMap = Map<K, V, H>;

    MyMap& map;
    size_t rollback_counter;

    Version commit_version = NoVersion;
    bool changes = false;
    bool deserialised = false;
    bool committed_writes = false;

  public:
    CommittableStateAccessor(
      typename Base::State& current_state,
      typename Base::State& committed_state,
      Version v,
      MyMap& m,
      size_t rollbacks) :
      Base(current_state, committed_state, v),
      map(m),
      rollback_counter(rollbacks)
    {}
  };

  template <class K, class V, class H>
  class Map : public AbstractMap
  {
  public:
    static bool deleted(Version version)
    {
      return version < 0;
    }

    using VersionV = VersionV<V>;
    using State = State<K, V, H>;
    using Read = Read<K, V, H>;
    using Write = Write<K, V, H>;
    using CommitHook = CommitHook<K, V, H>;

  private:
    using This = Map<K, V, H>;

    struct LocalCommit
    {
      LocalCommit() = default;
      LocalCommit(Version v, State s, Write w) :
        version(std::move(v)),
        state(std::move(s)),
        writes(std::move(w)),
        next(nullptr),
        prev(nullptr)
      {}

      Version version;
      State state;
      Write writes;
      LocalCommit* next;
      LocalCommit* prev;
    };
    using LocalCommits = snmalloc::DLList<LocalCommit, std::nullptr_t, true>;

    AbstractStore* store;
    std::string name;
    size_t rollback_counter;
    std::unique_ptr<LocalCommits> roll;
    CommitHook local_hook = nullptr;
    CommitHook global_hook = nullptr;
    LocalCommits commit_deltas;
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

  protected:
    AbstractTxView* create_view_internal(
      Version version,
      std::function<AbstractTxView*(State& state, Version v)>&& create_fn)
    {
      lock();

      // Find the last entry committed at or before this version.
      AbstractTxView* view = nullptr;

      for (auto current = roll->get_tail(); current != nullptr;
           current = current->prev)
      {
        if (current->version <= version)
        {
          view = create_fn(current->state, current->version);
          break;
        }
      }

      if (view == nullptr)
      {
        view = create_fn(roll->get_head()->state, roll->get_head()->version);
      }

      unlock();
      return view;
    }

  public:
    Map(
      AbstractStore* store_,
      std::string name_,
      SecurityDomain security_domain_,
      bool replicated_) :
      store(store_),
      name(name_),
      roll(std::make_unique<LocalCommits>()),
      rollback_counter(0),
      security_domain(security_domain_),
      replicated(replicated_)
    {
      roll->insert_back(create_new_local_commit(0, State(), Write()));
    }

    Map(const Map& that) = delete;

    virtual AbstractMap* clone(AbstractStore* other) override
    {
      return new Map(other, name, security_domain, replicated);
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
    void set_local_hook(CommitHook hook)
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
    void set_global_hook(CommitHook hook)
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
      auto p = dynamic_cast<const This*>(&that);
      if (p == nullptr)
        return false;

      if (name != p->name)
        return false;

      auto state1 = roll->get_tail();
      auto state2 = p->roll->get_tail();

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

    class TxView : public AbstractTxView
    {
      friend Map;

    private:
      This& map;
      State state;
      State committed;
      Read reads;
      Write writes;
      Version start_version;
      size_t rollback_counter;
      Version read_version;
      Version commit_version;
      bool changes;
      bool deserialised;
      bool committed_writes;

      TxView(This& parent, State& s, Version v, size_t r) :
        map(parent),
        state(s),
        committed(parent.roll->get_head()->state),
        start_version(v),
        rollback_counter(r),
        read_version(NoVersion),
        commit_version(NoVersion),
        changes(false),
        deserialised(false),
        committed_writes(false)
      {}

    public:
      // Expose these types so that other code can use them as MyTx::KeyType or
      // MyMap::TxView::KeyType, templated on the TxView or Map type rather than
      // explicitly on K and V
      using KeyType = K;
      using ValueType = V;

      TxView(const TxView& that) = delete;

      /** Get value for key
       *
       * This returns the value for the key inside the transaction. If the key
       * has been updated in the current transaction, that update will be
       * reflected in the return of this call.
       *
       * @param key Key
       *
       * @return optional containing value, empty if the key doesn't exist
       */
      std::optional<V> get(const K& key)
      {
        if (commit_version != NoVersion)
          return {};

        // A write followed by a read doesn't introduce a read dependency.
        // If we have written, return the value without updating the read set.
        auto write = writes.find(key);
        if (write != writes.end())
        {
          // Return empty for a key that has been removed.
          if (deleted(write->second.version))
            return {};

          return write->second.value;
        }

        // If the key doesn't exist, return empty and record that we depend on
        // the key not existing.
        auto search = state.get(key);
        if (!search.has_value())
        {
          reads.insert(std::make_pair(key, NoVersion));
          return {};
        }

        // Record the version that we depend on.
        auto& found = search.value();
        reads.insert(std::make_pair(key, found.version));

        // If the key has been deleted, return empty.
        if (deleted(found.version))
          return {};

        // Return the value.
        return found.value;
      }

      /** Get globally committed value for key
       *
       * This reads a globally replicated value for the specified key.
       * The value will have been the replicated value when the transaction
       * began, but the map may be compacted while the transaction is in
       * flight. If that happens, there may be a more recent committed
       * version. This is undetectable to the transaction.
       *
       * @param key Key
       *
       * @return optional containing value, empty if the key doesn't exist in
       * globally committed state
       */
      std::optional<V> get_globally_committed(const K& key)
      {
        if (commit_version != NoVersion)
          return {};

        // If there is no committed value, return empty.
        auto search = committed.get(key);
        if (!search.has_value())
          return {};

        // If the key has been deleted, return empty.
        auto& found = search.value();
        if (deleted(found.version))
          return {};

        // Return the value.
        return found.value;
      }

      /** Write value at key
       *
       * If the key already exists, the value will be replaced.
       * This will fail if the transaction is already committed.
       *
       * @param key Key
       * @param value Value
       *
       * @return true if successful, false otherwise
       */
      bool put(const K& key, const V& value)
      {
        if (commit_version != NoVersion)
          return false;

        // Record in the write set.
        writes[key] = {0, value};
        return true;
      }

      /** Remove key
       *
       * This will fail if the key does not exist, or if the transaction
       * is already committed.
       *
       * @param key Key
       *
       * @return true if successful, false otherwise
       */
      bool remove(const K& key)
      {
        if (commit_version != NoVersion)
          return false;

        auto write = writes.find(key);
        auto search = state.get(key).has_value();

        if (write != writes.end())
        {
          if (!search)
          {
            // this key only exists locally, there is no reason to maintain and
            // serialise it
            writes.erase(key);
          }
          else
          {
            // If we have written, change the write set to indicate a remove.
            write->second = {NoVersion, V()};
          }

          return true;
        }

        // If the key doesn't exist, return false.
        if (!search)
          return false;

        // Record in the write set.
        writes.emplace(
          std::piecewise_construct,
          std::forward_as_tuple(key),
          std::forward_as_tuple(NoVersion, V()));
        return true;
      }

      /** Iterate over all entries in the map
       *
       * @param F functor, taking a key and a value, return value determines
       * whether the iteration should continue (true) or stop (false)
       */
      template <class F>
      bool foreach(F&& f)
      {
        if (commit_version != NoVersion)
          return false;

        // Record a global read dependency.
        read_version = start_version;
        auto& w = writes;

        state.foreach([&w, &f](const K& k, const VersionV& v) {
          auto write = w.find(k);

          if ((write == w.end()) && !deleted(v.version))
            return f(k, v.value);
          return true;
        });

        for (auto write = writes.begin(); write != writes.end(); ++write)
        {
          if (!deleted(write->second.version))
            if (!f(write->first, write->second.value))
              return false;
        }
        return true;
      }

      bool is_replicated()
      {
        return map.is_replicated();
      }

    private:
      virtual bool has_writes()
      {
        return committed_writes || !writes.empty();
      }

      virtual bool has_changes()
      {
        return changes;
      }

      virtual bool prepare()
      {
        if (writes.empty())
          return true;

        // If the parent map has rolled back since this transaction began, this
        // transaction must fail.
        if (rollback_counter != map.rollback_counter)
          return false;

        // If we have iterated over the map, check for a global version match.
        auto current = map.roll->get_tail();

        if ((read_version != NoVersion) && (read_version != current->version))
        {
          LOG_DEBUG_FMT("Read version {} is invalid", read_version);
          return false;
        }

        // Check each key in our read set.
        for (auto it = reads.begin(); it != reads.end(); ++it)
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

      virtual void commit(Version v)
      {
        if (writes.empty())
        {
          commit_version = start_version;
          return;
        }

        // Record our commit time.
        commit_version = v;
        committed_writes = true;

        if (!writes.empty())
        {
          auto state = map.roll->get_tail()->state;

          for (auto it = writes.begin(); it != writes.end(); ++it)
          {
            if (it->second.version >= 0)
            {
              // Write the new value with the global version.
              changes = true;
              state = state.put(it->first, VersionV{v, it->second.value});
            }
            else
            {
              // Write an empty value with the deleted global version only if
              // the key exists.
              auto search = state.get(it->first);
              if (search.has_value())
              {
                changes = true;
                state = state.put(it->first, VersionV{-v, V()});
              }
            }
          }

          if (changes)
          {
            map.roll->insert_back(
              map.create_new_local_commit(v, state, writes));
          }
        }
      }

      virtual void post_commit()
      {
        // This is run separately from commit so that all commits in the Tx
        // have been applied before local hooks are run. The maps in the Tx
        // are still locked when post_commit is run.
        if (writes.empty())
          return;

        if (map.local_hook)
        {
          auto roll = map.roll->get_tail();
          map.local_hook(roll->version, roll->state, roll->writes);
        }
      }

      virtual void serialise(KvStoreSerialiser& s, bool include_reads)
      {
        if (!changes)
          return;

        s.start_map(map.name, map.get_security_domain());

        if (include_reads)
        {
          s.serialise_read_version(read_version);

          s.serialise_count_header(reads.size());
          for (auto it = reads.begin(); it != reads.end(); ++it)
            s.serialise_read(it->first, it->second);
        }
        else
        {
          s.serialise_read_version(NoVersion);
          s.serialise_count_header(0);
        }

        uint64_t write_ctr = 0;
        uint64_t remove_ctr = 0;
        for (auto it = writes.begin(); it != writes.end(); ++it)
        {
          if (!is_remove(it->second.version))
          {
            ++write_ctr;
          }
          else
          {
            auto search = map.roll->get_tail()->state.get(it->first);
            if (search.has_value())
              ++remove_ctr;
          }
        }
        s.serialise_count_header(write_ctr);
        for (auto it = writes.begin(); it != writes.end(); ++it)
        {
          if (!is_remove(it->second.version))
          {
            s.serialise_write(it->first, it->second.value);
          }
        }

        s.serialise_count_header(remove_ctr);
        for (auto it = writes.begin(); it != writes.end(); ++it)
        {
          if (is_remove(it->second.version))
          {
            s.serialise_remove(it->first);
          }
        }
      }

      virtual bool deserialise(KvStoreDeserialiser& d, Version version)
      {
        commit_version = version;
        uint64_t ctr;

        auto rv = d.template deserialise_read_version<Version>();
        if (rv != NoVersion)
          read_version = rv;

        ctr = d.deserialise_read_header();
        for (size_t i = 0; i < ctr; ++i)
        {
          auto r = d.template deserialise_read<K>();
          reads[std::get<0>(r)] = std::get<1>(r);
        }

        ctr = d.deserialise_write_header();
        for (size_t i = 0; i < ctr; ++i)
        {
          auto w = d.template deserialise_write<K, V>();
          writes[std::get<0>(w)] = {0, std::get<1>(w)};
        }

        ctr = d.deserialise_remove_header();
        for (size_t i = 0; i < ctr; ++i)
        {
          auto r = d.template deserialise_remove<K>();
          writes[r] = {NoVersion, V()};
        }

        return true;
      }

      static bool is_remove(const Version& v)
      {
        return v == NoVersion;
      }
    };

    AbstractTxView* create_view(Version version) override
    {
      return create_view_internal(version, [this](State& s, Version v) {
        return new TxView(*this, s, v, rollback_counter);
      });
    }

  private:
    friend TxView;

    void compact(Version v) override
    {
      // This discards available rollback state before version v, and populates
      // the commit_deltas to be passed to the global commit hook, if there is
      // one, up to version v. The Map expects to be locked during compaction.
      while (roll->get_head() != roll->get_tail())
      {
        auto r = roll->get_head();

        // Globally committed but not discardable.
        if (r->version == v)
        {
          // We know that write set is not empty.
          if (global_hook)
          {
            commit_deltas.insert_back(
              create_new_local_commit(r->version, r->state, move(r->writes)));
          }
          return;
        }

        // Discardable, so move to commit_deltas.
        if (global_hook && !r->writes.empty())
        {
          commit_deltas.insert_back(
            create_new_local_commit(r->version, r->state, move(r->writes)));
        }

        // Stop if the next state may be rolled back or is the only state.
        // This ensures there is always a state present.
        if (r->next->version > v)
          return;

        auto c = roll->pop();
        empty_commits.insert(c);
      }

      // There is only one roll. We may need to call the commit hook.
      auto r = roll->get_head();

      if (global_hook && !r->writes.empty())
      {
        commit_deltas.insert_back(
          create_new_local_commit(r->version, r->state, move(r->writes)));
      }
    }

    void post_compact() override
    {
      if (global_hook)
      {
        for (auto r = commit_deltas.get_head(); r != nullptr; r = r->next)
        {
          global_hook(r->version, r->state, r->writes);
        }
      }

      commit_deltas.clear();
    }

    void rollback(Version v) override
    {
      // This rolls the current state back to version v.
      // The Map expects to be locked during rollback.
      bool advance = false;

      while (roll->get_head() != roll->get_tail())
      {
        auto r = roll->get_tail();

        // The initial empty state has v = 0, so will not be discarded if it
        // is present.
        if (r->version <= v)
          break;

        advance = true;
        auto c = roll->pop_tail();
        empty_commits.insert(c);
      }

      if (advance)
        rollback_counter++;
    }

    void clear() override
    {
      // This discards all entries in the roll and resets the compacted value
      // and rollback counter. The Map expects to be locked before clearing it.
      roll->clear();
      roll->insert_back(create_new_local_commit(0, State(), Write()));
      rollback_counter = 0;
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
      This* map = dynamic_cast<This*>(map_);
      if (map == nullptr)
        throw std::logic_error(
          "Attempted to swap maps with incompatible types");

      std::swap(rollback_counter, map->rollback_counter);
      std::swap(roll, map->roll);
    }
  };

  struct MapView
  {
    // Weak pointer to source map
    AbstractMap* map;

    // Owning pointer of TxView over that map
    std::unique_ptr<AbstractTxView> view;
  };
}