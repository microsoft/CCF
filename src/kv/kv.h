// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/champ_map.h"
#include "ds/dl_list.h"
#include "ds/logger.h"
#include "ds/spin_lock.h"
#include "kv_types.h"

#include <functional>
#include <iostream>
#include <limits>
#include <list>
#include <map>
#include <mutex>
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

  template <class S, class D>
  class Tx;

  template <class S, class D>
  class Store;

  template <class K, class V, class H, class S, class D>
  class Map : public AbstractMap<S, D>
  {
  public:
    static bool deleted(Version version)
    {
      return version < 0;
    }

    struct VersionV
    {
      Version version;
      V value;

      VersionV() = default;
      VersionV(Version ver, V val) : version(ver), value(val) {}
    };

    using State = champ::Map<K, VersionV, H>;
    using Read = std::unordered_map<K, Version, H>;
    using Write = std::unordered_map<K, VersionV, H>;
    /// Signature for transaction commit handlers
    using CommitHook = std::function<void(Version, const State&, const Write&)>;

  private:
    using This = Map<K, V, H, S, D>;

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

    Store<S, D>* store;
    std::string name;
    size_t rollback_counter;
    std::unique_ptr<LocalCommits> roll;
    CommitHook local_hook;
    CommitHook global_hook;
    LocalCommits commit_deltas;
    SpinLock sl;
    const SecurityDomain security_domain;
    const bool replicated;

    LocalCommits empty_commits;

    Map(
      Store<S, D>* store_,
      std::string name_,
      SecurityDomain security_domain_,
      bool replicated_,
      CommitHook local_hook_,
      CommitHook global_hook_) :
      store(store_),
      name(name_),
      roll(std::make_unique<LocalCommits>()),
      rollback_counter(0),
      security_domain(security_domain_),
      replicated(replicated_),
      local_hook(local_hook_),
      global_hook(global_hook_)
    {
      roll->insert_back(create_new_local_commit(0, State(), Write()));
    }

    Map(const Map& that) = delete;

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
    virtual AbstractMap<S, D>* clone(AbstractStore* store) override
    {
      Store<S, D>* store_ = dynamic_cast<Store<S, D>*>(store);

      if (store_ == nullptr)
        throw std::logic_error("Failed to cast store in Map clone");

      return new Map(
        store_, name, security_domain, replicated, nullptr, nullptr);
    }

    /** Get the name of the map
     *
     * @return const std::string&
     */
    const std::string& get_name() const
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

    /** Set handler to be called on global transaction commit
     *
     * @param hook function to be called on global transaction commit
     */
    void set_global_hook(CommitHook hook)
    {
      std::lock_guard<SpinLock> guard(sl);
      global_hook = hook;
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

    bool operator==(const AbstractMap<S, D>& that) const override
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

    bool operator!=(const AbstractMap<S, D>& that) const override
    {
      return !(*this == that);
    }

    class TxView : public AbstractTxView<S, D>
    {
      friend Map;
      friend Tx<S, D>;

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

      virtual ~TxView()
      {
        // If we are destructed, prevent future access.
        commit_version = 0;
      }

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

      Version start_order()
      {
        return start_version;
      }

      Version end_order()
      {
        if (commit_version == NoVersion)
          throw std::logic_error("Uncommitted transaction has no end order");

        return commit_version;
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

      virtual void serialise(S& s, bool include_reads)
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

      virtual bool deserialise(D& d, Version version)
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

  private:
    friend TxView;
    friend Tx<S, D>;
    friend Store<S, D>;

    TxView* create_view(Version version) override
    {
      lock();

      // Find the last entry committed at or before this version.
      TxView* view = nullptr;

      for (auto current = roll->get_tail(); current != nullptr;
           current = current->prev)
      {
        if (current->version <= version)
        {
          view = new TxView(
            *this, current->state, current->version, rollback_counter);
          break;
        }
      }

      if (view == nullptr)
      {
        view = new TxView(
          *this,
          roll->get_head()->state,
          roll->get_head()->version,
          rollback_counter);
      }

      unlock();
      return view;
    }

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

    void swap(AbstractMap<S, D>* map_) override
    {
      This* map = dynamic_cast<This*>(map_);
      if (map == nullptr)
        throw std::logic_error(
          "Attempted to swap maps with incompatible types");

      std::swap(rollback_counter, map->rollback_counter);
      std::swap(roll, map->roll);
    }
  };

  template <class S, class D>
  struct MapView
  {
    // Weak pointer to source map
    AbstractMap<S, D>* map;

    // Owning pointer of TxView over that map
    std::unique_ptr<AbstractTxView<S, D>> view;
  };

  // When a collection of Maps are locked, the locks must be acquired in a
  // stable order to avoid deadlocks. This ordered map will claim in name-order
  template <class S, class D>
  using OrderedViews = std::map<std::string, MapView<S, D>>;

  template <typename SP, typename DP>
  static inline std::
    map<kv::SecurityDomain, std::vector<AbstractTxView<SP, DP>*>>
    get_maps_grouped_by_domain(const OrderedViews<SP, DP>& maps)
  {
    std::map<kv::SecurityDomain, std::vector<AbstractTxView<SP, DP>*>>
      grouped_maps;
    for (auto it = maps.cbegin(); it != maps.cend(); ++it)
    {
      grouped_maps[it->second.map->get_security_domain()].push_back(
        it->second.view.get());
    }
    return grouped_maps;
  }

  template <class S, class D>
  class Tx
  {
  private:
    OrderedViews<S, D> view_list;
    bool committed;
    bool success;
    Version read_version;
    Version version;
    bool read_globally_committed = false;

    kv::TxHistory::RequestID req_id;

    template <class M>
    std::tuple<typename M::TxView*> get_tuple(M& m)
    {
      // If the M is present, its AbtractTxView must be an M::TxView.
      auto search = view_list.find(m.name);
      if (search != view_list.end())
        return std::make_tuple(
          static_cast<typename M::TxView*>(search->second.view.get()));

      auto it = view_list.begin();
      if (it != view_list.end())
      {
        // All Maps must be in the same store.
        if (it->second.map->get_store() != m.get_store())
          throw std::logic_error(
            "Transaction must be over maps in the same store");
      }

      if (read_version == NoVersion)
      {
        // Grab opacity version that all Maps should be queried at.
        if (read_globally_committed)
          read_version = m.get_store()->commit_version();
        else
          read_version = m.get_store()->current_version();
      }

      typename M::TxView* view = m.create_view(read_version);
      view_list[m.name] = {&m, std::unique_ptr<AbstractTxView<S, D>>(view)};
      return std::make_tuple(view);
    }

    template <class M, class... Ms>
    std::tuple<typename M::TxView*, typename Ms::TxView*...> get_tuple(
      M& m, Ms&... ms)
    {
      return std::tuple_cat(get_tuple(m), get_tuple(ms...));
    }

    void reset()
    {
      view_list.clear();
      committed = false;
      success = false;
      read_version = NoVersion;
      version = NoVersion;
    }

  public:
    Tx() :
      view_list(),
      committed(false),
      success(false),
      read_version(NoVersion),
      version(NoVersion)
    {}

    Tx(const Tx& that) = delete;

    void set_view_list(OrderedViews<S, D>& view_list_)
    {
      // if view list is not empty then any coinciding keys will not be
      // overwritten
      view_list.merge(view_list_);
    }

    void set_req_id(const kv::TxHistory::RequestID& req_id_)
    {
      req_id = req_id_;
    }

    /** Version for the transaction set
     *
     * @return Committed version, or `kv::NoVersion` otherwise
     */
    Version get_version()
    {
      return version;
    }

    Version get_read_version()
    {
      return read_version;
    }

    /** Get a transaction view on a map.
     *
     * This adds the map to the transaction set if it is not yet present.
     *
     * @param m Map
     */
    template <class M>
    typename M::TxView* get_view(M& m)
    {
      return std::get<0>(get_tuple(m));
    }

    /** Get transaction views over multiple maps.
     *
     * @param m Map
     * @param ms Map
     */
    template <class M, class... Ms>
    std::tuple<typename M::TxView*, typename Ms::TxView*...> get_view(
      M& m, Ms&... ms)
    {
      return std::tuple_cat(get_tuple(m), get_tuple(ms...));
    }

    /** Commit transaction
     *
     * A transaction can either succeed and replicate (`kv::CommitSuccess::OK`),
     * fail because of a conflict with other transactions
     * (`kv::CommitSuccess::CONFLICT`), or succeed locally, but fail to
     * replicate (`kv::CommitSuccess::NO_REPLICATE`).
     *
     * Transactions that fail are rolled back, no matter the reason.
     *
     * @return transaction outcome
     */
    CommitSuccess commit()
    {
      if (committed)
        throw std::logic_error("Transaction already committed");

      if (view_list.empty())
      {
        committed = true;
        success = true;
        return CommitSuccess::OK;
      }

      auto store = view_list.begin()->second.map->get_store();
      auto c = commit(view_list, [store]() { return store->next_version(); });
      success = c.has_value();

      if (!success)
      {
        // Conflicting views (and contained writes) and all version tracking are
        // discarded. They must be reconstructed at updated, non-conflicting
        // versions
        reset();

        LOG_TRACE_FMT("Could not commit transaction due to conflict");
        return CommitSuccess::CONFLICT;
      }
      else
      {
        committed = true;
        version = c.value();

        // From here, we have received a unique commit version and made
        // modifications to our local kv. If we fail in any way, we cannot
        // recover.
        try
        {
          auto data = serialise();

          if (data.empty())
          {
            auto h = store->get_history();
            if (h != nullptr)
            {
              // This tx does not have a write set, so this is a read only tx
              // because of this we are returning NoVersion
              h->add_result(req_id, NoVersion);
            }
            return CommitSuccess::OK;
          }

          return store->commit(
            version, MovePendingTx(std::move(data), std::move(req_id)), false);
        }
        catch (const std::exception& e)
        {
          committed = false;

          LOG_FAIL_FMT("Error during serialisation: {}", e.what());

          // Discard original exception type, throw as now fatal
          // KvSerialiserException
          throw KvSerialiserException(e.what());
        }
      }
    }

    /** Commit version if committed
     *
     * @return Commit version
     */
    Version commit_version()
    {
      if (!committed)
        throw std::logic_error("Transaction not yet committed");

      if (!success)
        throw std::logic_error("Transaction aborted");

      return version;
    }

    static std::optional<Version> commit(
      OrderedViews<S, D>& views, std::function<Version()> f)
    {
      // All maps with pending writes are locked, transactions are prepared
      // and possibly committed, and then all maps with pending writes are
      // unlocked. This is to prevent transactions from being committed in an
      // interleaved fashion.
      Version version = 0;
      bool has_writes = false;

      for (auto it = views.begin(); it != views.end(); ++it)
      {
        if (it->second.view->has_writes())
        {
          it->second.map->lock();
          has_writes = true;
        }
      }

      bool ok = true;

      for (auto it = views.begin(); it != views.end(); ++it)
      {
        if (!it->second.view->prepare())
        {
          ok = false;
          break;
        }
      }

      if (ok && has_writes)
      {
        // Get the version number to be used for this commit.
        version = f();

        for (auto it = views.begin(); it != views.end(); ++it)
          it->second.view->commit(version);

        for (auto it = views.begin(); it != views.end(); ++it)
          it->second.view->post_commit();
      }

      for (auto it = views.begin(); it != views.end(); ++it)
      {
        if (it->second.view->has_writes())
          it->second.map->unlock();
      }

      if (!ok)
        return {};

      return version;
    }

    std::vector<uint8_t> serialise(bool include_reads = false)
    {
      if (!committed)
        throw std::logic_error("Transaction not yet committed");

      if (!success)
        throw std::logic_error("Transaction aborted");

      // If no transactions made changes, return a zero length vector.
      bool changes = false;

      for (auto it = view_list.begin(); it != view_list.end(); ++it)
      {
        if (it->second.view->has_changes())
        {
          changes = true;
          break;
        }
      }

      if (!changes)
      {
        return {};
      }
      // Retrieve encryptor.
      auto map = view_list.begin()->second.map;
      auto e = map->get_store()->get_encryptor();

      S replicated_serialiser(e, version);
      // flags that indicate if we have actually written any data in the
      // serializers
      auto grouped_maps = get_maps_grouped_by_domain(view_list);

      for (auto domain_it : grouped_maps)
      {
        for (auto curr_map : domain_it.second)
        {
          if (curr_map->is_replicated())
          {
            curr_map->serialise(replicated_serialiser, include_reads);
          }
        }
      }

      // Return serialised Tx.
      return replicated_serialiser.get_raw_data();
    }

    // Used by frontend for reserved transactions
    Tx(Version reserved) :
      view_list(),
      committed(false),
      success(false),
      read_version(reserved - 1),
      version(reserved)
    {}

    // Used by frontend to commit reserved transactions
    PendingTxInfo commit_reserved()
    {
      if (committed)
        throw std::logic_error("Transaction already committed");

      committed = true;

      if (view_list.empty())
        throw std::logic_error("Reserved transaction cannot be empty");

      auto c = commit(view_list, [this]() { return version; });
      success = c.has_value();

      if (!success)
        throw std::logic_error("Failed to commit reserved transaction");

      return {CommitSuccess::OK, {0, 0, 0}, std::move(serialise())};
    }

    // Set all reads on transaction to read at the global commit version,
    // rather than the local commit.
    void set_read_committed()
    {
      if (read_version == NoVersion)
      {
        read_globally_committed = true;
      }
      else
      {
        throw std::logic_error(
          "Cannot set_read_committed, read_version is already set");
      }
    }
  };

  template <class S, class D>
  class Store : public AbstractStore
  {
  public:
    template <class K, class V, class H = std::hash<K>>
    using Map = Map<K, V, H, S, D>;
    using Tx = Tx<S, D>;

  private:
    // All collections of Map must be ordered so that we lock their contained
    // maps in a stable order. The order here is by map name
    using Maps = std::map<std::string, std::unique_ptr<AbstractMap<S, D>>>;
    Maps maps;

    std::shared_ptr<Consensus> consensus = nullptr;
    std::shared_ptr<TxHistory> history = nullptr;
    std::shared_ptr<AbstractTxEncryptor> encryptor = nullptr;
    Version version = 0;
    Version compacted = 0;

    SpinLock maps_lock;
    SpinLock version_lock;

    std::unordered_map<Version, std::pair<PendingTx, bool>> pending_txs;
    Version last_replicated = 0;
    Version last_committable = 0;
    Version rollback_count = 0;
    kv::ReplicateType replicate_type = kv::ReplicateType::ALL;
    std::unordered_set<std::string> replicated_tables;

    template <typename SP, typename DP>
    inline std::map<kv::SecurityDomain, std::vector<AbstractMap<SP, DP>*>>
    get_maps_grouped_by_domain(
      const std::map<std::string, std::unique_ptr<AbstractMap<SP, DP>>>& maps)
    {
      std::map<kv::SecurityDomain, std::vector<AbstractMap<SP, DP>*>>
        grouped_maps;
      for (auto it = maps.begin(); it != maps.end(); ++it)
      {
        grouped_maps[it->second->get_security_domain()].push_back(
          it->second.get());
      }
      return grouped_maps;
    }

    DeserialiseSuccess commit_deserialised(
      OrderedViews<S, D>& views, Version& v)
    {
      auto c = Tx::commit(views, [v]() { return v; });
      if (!c.has_value())
      {
        LOG_FAIL_FMT("Failed to commit deserialised Tx at version {}", v);
        return DeserialiseSuccess::FAILED;
      }
      {
        std::lock_guard<SpinLock> vguard(version_lock);
        version = v;
        last_replicated = version;
      }
      return DeserialiseSuccess::PASS;
    }

  public:
    void clone_schema(Store& target)
    {
      std::lock_guard<SpinLock> mguard(maps_lock);

      if ((maps.size() != 0) || (version != 0))
        throw std::logic_error("Cannot clone schema on a non-empty store");

      for (auto& [name, map] : target.maps)
      {
        maps[name] = std::unique_ptr<AbstractMap<S, D>>(map->clone(this));
      }
    }

    Store() {}

    Store(
      const ReplicateType& replicate_type_,
      const std::unordered_set<std::string>& replicated_tables_) :
      replicate_type(replicate_type_),
      replicated_tables(replicated_tables_)
    {}

    Store(std::shared_ptr<Consensus> consensus_) : consensus(consensus_) {}

    Store(const Store& that) = delete;

    std::shared_ptr<Consensus> get_consensus() override
    {
      return consensus;
    }

    void set_consensus(std::shared_ptr<Consensus> consensus_)
    {
      consensus = consensus_;
    }

    std::shared_ptr<TxHistory> get_history() override
    {
      return history;
    }

    void set_history(std::shared_ptr<TxHistory> history_)
    {
      history = history_;
    }

    void set_encryptor(std::shared_ptr<AbstractTxEncryptor> encryptor_)
    {
      encryptor = encryptor_;
    }

    std::shared_ptr<AbstractTxEncryptor> get_encryptor() override
    {
      return encryptor;
    }

    template <class K, class V, class H = std::hash<K>>
    Map<K, V, H>* get(std::string name)
    {
      return get<Map<K, V, H>>(name);
    }

    /** Get Map by name
     *
     * @param name Map name
     *
     * @return Map
     */
    template <class M>
    M* get(std::string name)
    {
      std::lock_guard<SpinLock> mguard(maps_lock);

      auto search = maps.find(name);
      if (search != maps.end())
      {
        auto result = dynamic_cast<M*>(search->second.get());

        if (result == nullptr)
          return nullptr;

        return result;
      }

      return nullptr;
    }

    /** Create a Map
     *
     * Note this call will throw a logic_error if a map by that name already
     * exists.
     *
     * @param name Map name
     * @param global_hook Handler to execute on global commit
     *
     * @return Newly created Map
     */
    template <class K, class V, class H = std::hash<K>>
    Map<K, V, H>& create(
      std::string name,
      SecurityDomain security_domain = kv::SecurityDomain::PRIVATE,
      typename Map<K, V, H>::CommitHook local_hook = nullptr,
      typename Map<K, V, H>::CommitHook global_hook = nullptr)
    {
      return create<Map<K, V, H>>(
        name, security_domain, local_hook, global_hook);
    }

    /** Create a Map
     *
     * Note this call will throw a logic_error if a map by that name already
     * exists.
     *
     * @param name Map name
     * @param global_hook Handler to execute on global commit
     *
     * @return Newly created Map
     */
    template <class M>
    M& create(
      std::string name,
      SecurityDomain security_domain = kv::SecurityDomain::PRIVATE,
      typename M::CommitHook local_hook = nullptr,
      typename M::CommitHook global_hook = nullptr)
    {
      std::lock_guard<SpinLock> mguard(maps_lock);

      auto search = maps.find(name);
      if (search != maps.end())
        throw std::logic_error("Map already exists");
      auto replicated = true;
      if (replicate_type == kv::ReplicateType::NONE)
      {
        replicated = false;
      }
      else if (replicate_type == kv::ReplicateType::SOME)
      {
        if (replicated_tables.find(name) == replicated_tables.end())
        {
          replicated = false;
        }
      }

      auto result =
        new M(this, name, security_domain, replicated, local_hook, global_hook);
      maps[name] = std::unique_ptr<AbstractMap<S, D>>(result);
      return *result;
    }

    void compact(Version v) override
    {
      // This is called when the store will never be rolled back to any
      // state before the specified version.
      // No transactions can be prepared or committed during compaction.
      std::lock_guard<SpinLock> mguard(maps_lock);

      if (v > current_version())
        return;

      for (auto& map : maps)
        map.second->lock();

      for (auto& map : maps)
        map.second->compact(v);

      for (auto& map : maps)
        map.second->unlock();

      {
        std::lock_guard<SpinLock> vguard(version_lock);
        compacted = v;

        auto h = get_history();
        if (h)
          h->compact(v);

        auto e = get_encryptor();
        if (e)
          e->compact(v);
      }

      for (auto& map : maps)
        map.second->post_compact();
    }

    void rollback(Version v) override
    {
      // This is called to roll the store back to the state it was in
      // at the specified version.
      // No transactions can be prepared or committed during rollback.
      std::lock_guard<SpinLock> mguard(maps_lock);

      if (v >= current_version())
        return;

      if (v < commit_version())
        return;

      for (auto& map : maps)
        map.second->lock();

      for (auto& map : maps)
        map.second->rollback(v);

      for (auto& map : maps)
        map.second->unlock();

      std::lock_guard<SpinLock> vguard(version_lock);
      version = v;
      last_replicated = v;
      last_committable = v;
      rollback_count++;
      pending_txs.clear();
      auto h = get_history();
      if (h)
        h->rollback(v);
      auto e = get_encryptor();
      if (e)
        e->rollback(v);
    }

    DeserialiseSuccess deserialise_views(
      const std::vector<uint8_t>& data,
      bool public_only = false,
      Term* term = nullptr,
      Tx* tx = nullptr)
    {
      // If we pass in a transaction we don't want to commit, just deserialise
      // and put the views into that transaction.
      // Tread carefully here: at the moment passing in a transaction assumes we
      // are using pbft as the consensus and that we are deserialising for
      // playback purposes
      auto commit = (tx == nullptr);

      // This will return FAILED if the serialised transaction is being
      // applied out of order.
      // Processing transactions locally and also deserialising to the
      // same store will result in a store version mismatch and
      // deserialisation will then fail.
      auto e = get_encryptor();

      // create the first deserialiser
      auto d = std::make_unique<D>(
        e,
        public_only ? kv::SecurityDomain::PUBLIC :
                      std::optional<kv::SecurityDomain>());

      if (!d->init(data.data(), data.size()))
      {
        LOG_FAIL_FMT("Initialisation of deserialise object failed");
        return DeserialiseSuccess::FAILED;
      }

      Version v = d->template deserialise_version<Version>();
      // Throw away any local commits that have not propagated via the
      // consensus.
      rollback(v - 1);

      // Make sure this is the next transaction.
      auto cv = current_version();
      if (cv != (v - 1))
      {
        LOG_FAIL_FMT(
          "Tried to deserialise {} but current_version is {}", v, cv);
        return DeserialiseSuccess::FAILED;
      }

      // Deserialised transactions express read dependencies as versions,
      // rather than with the actual value read. As a result, they don't
      // need snapshot isolation on the map state, and so do not need to
      // lock all the maps before creating the transaction.
      std::lock_guard<SpinLock> mguard(maps_lock);
      OrderedViews<S, D> views;

      for (auto r = d->start_map(); r.has_value(); r = d->start_map())
      {
        const auto map_name = r.value();

        auto search = maps.find(map_name);
        if (search == maps.end())
        {
          LOG_FAIL_FMT("No such map {} at version {}", map_name, v);
          return DeserialiseSuccess::FAILED;
        }

        auto view_search = views.find(map_name);
        if (view_search != views.end())
        {
          LOG_FAIL_FMT("Multiple writes on {} at version {}", map_name, v);
          return DeserialiseSuccess::FAILED;
        }

        auto view = search->second->create_view(v);
        // if we are not committing now then use NoVersion to deserialise
        // otherwise the view will be considered as having a committed
        // version
        auto deserialise_version = (commit ? v : NoVersion);
        if (!view->deserialise(*d, deserialise_version))
        {
          LOG_FAIL_FMT(
            "Could not deserialise Tx for map {} at version {}",
            map_name,
            deserialise_version);
          return DeserialiseSuccess::FAILED;
        }

        views[map_name] = {search->second.get(),
                           std::unique_ptr<AbstractTxView<S, D>>(view)};
      }

      if (!d->end())
      {
        LOG_FAIL_FMT("Unexpected content in Tx at version {}", v);
        return DeserialiseSuccess::FAILED;
      }

      auto success = DeserialiseSuccess::PASS;

      if (commit)
      {
        success = commit_deserialised(views, v);
        if (success == DeserialiseSuccess::FAILED)
        {
          return success;
        }
        auto h = get_history();
        if (h)
        {
          auto search = views.find("ccf.signatures");
          if (search != views.end())
          {
            // Transactions containing a signature must only contain
            // a signature and must be verified
            if (views.size() > 1)
            {
              LOG_FAIL_FMT(
                "Unexpected contents in signature transaction {}", v);
              return DeserialiseSuccess::FAILED;
            }

            if (!h->verify(term))
            {
              LOG_FAIL_FMT("Signature in transaction {} failed to verify", v);
              return DeserialiseSuccess::FAILED;
            }
            success = DeserialiseSuccess::PASS_SIGNATURE;
          }

          h->append(data.data(), data.size());
        }
      }
      else
      {
        // Transactions containing a pre prepare or a pbft request should not
        // contain anything else
        if (views.size() > 1)
        {
          LOG_FAIL_FMT("Unexpected contents in pbft transaction {}", v);
          return DeserialiseSuccess::FAILED;
        }

        auto search = views.find("ccf.pbft.preprepares");
        if (search != views.end())
        {
          success = DeserialiseSuccess::PASS_PRE_PREPARE;
        }
        else
        {
          auto search = views.find("ccf.pbft.requests");
          if (search == views.end())
          {
            // we have deserialised an entry that didn't belong to the pbft
            // requests nor the pbft pre prepares table
            return DeserialiseSuccess::FAILED;
          }
        }
      }

      if (tx)
      {
        tx->set_view_list(views);
      }

      return success;
    }

    DeserialiseSuccess deserialise(
      const std::vector<uint8_t>& data,
      bool public_only = false,
      Term* term = nullptr) override
    {
      return deserialise_views(data, public_only, term);
    }

    bool operator==(const Store<S, D>& that) const
    {
      // Only used for debugging, not thread safe.
      if (version != that.version)
        return false;

      if (maps.size() != that.maps.size())
        return false;

      for (auto it = maps.begin(); it != maps.end(); ++it)
      {
        auto search = that.maps.find(it->first);

        if (search == that.maps.end())
          return false;

        if (*it->second != *search->second)
          return false;
      }

      return true;
    }

    bool operator!=(const Store<S, D>& that) const
    {
      // Only used for debugging, not thread safe.
      return !(*this == that);
    }

    Version current_version() override
    {
      // Must lock in case the version is being incremented.
      std::lock_guard<SpinLock> vguard(version_lock);
      return version;
    }

    Version commit_version() override
    {
      // Must lock in case the store is being compacted.
      std::lock_guard<SpinLock> vguard(version_lock);
      return compacted;
    }

    CommitSuccess commit(
      Version version, PendingTx pending_tx, bool globally_committable) override
    {
      auto r = get_consensus();
      if (!r)
        return CommitSuccess::OK;

      LOG_DEBUG_FMT(
        "Store::commit {}{}",
        version,
        (globally_committable ? " globally_committable" : ""));

      BatchVector batch;
      Version previous_last_replicated = 0;
      Version next_last_replicated = 0;
      Version previous_rollback_count = 0;

      {
        std::lock_guard<SpinLock> vguard(version_lock);
        if (globally_committable && version > last_committable)
          last_committable = version;

        pending_txs.insert(
          {version,
           std::make_pair(std::move(pending_tx), globally_committable)});

        auto h = get_history();
        auto c = get_consensus();

        for (Version offset = 1; true; ++offset)
        {
          auto search = pending_txs.find(last_replicated + offset);
          if (search == pending_txs.end())
            break;

          auto& [pending_tx_, committable_] = search->second;
          auto [success_, reqid, data_] = pending_tx_();
          auto data_shared =
            std::make_shared<std::vector<uint8_t>>(std::move(data_));

          // NB: this cannot happen currently. Regular Tx only make it here if
          // they did succeed, and signatures cannot conflict because they
          // execute in order with a read_version that's version - 1, so even
          // two contiguous signatures are fine
          if (success_ != CommitSuccess::OK)
            LOG_DEBUG_FMT("Failed Tx commit {}", last_replicated + offset);

          if (h)
          {
            h->add_pending(reqid, version, data_shared);
          }

          LOG_DEBUG_FMT(
            "Batching {} ({})", last_replicated + offset, data_shared->size());
          batch.emplace_back(
            last_replicated + offset, data_shared, committable_);
          pending_txs.erase(search);
        }

        if (batch.size() == 0)
          return CommitSuccess::OK;

        previous_rollback_count = rollback_count;
        previous_last_replicated = last_replicated;
        next_last_replicated = last_replicated + batch.size();
      }

      if (r->replicate(batch))
      {
        std::lock_guard<SpinLock> vguard(version_lock);
        if (
          last_replicated == previous_last_replicated &&
          previous_rollback_count == rollback_count)
        {
          last_replicated = next_last_replicated;
        }
        return CommitSuccess::OK;
      }
      else
      {
        LOG_DEBUG_FMT("Failed to replicate");
        return CommitSuccess::NO_REPLICATE;
      }
    }

    Version next_version() override
    {
      std::lock_guard<SpinLock> vguard(version_lock);

      // Get the next global version. If we would go negative, wrap to 0.
      ++version;

      if (version < 0)
        version = 0;

      return version;
    }

    size_t commit_gap() override
    {
      std::lock_guard<SpinLock> vguard(version_lock);
      return version - last_committable;
    }

    void clear()
    {
      std::lock_guard<SpinLock> mguard(maps_lock);

      // This deletes the entire content of all maps in the store.
      for (auto& map : maps)
        map.second->lock();

      for (auto& map : maps)
        map.second->clear();

      for (auto& map : maps)
        map.second->unlock();

      {
        std::lock_guard<SpinLock> vguard(version_lock);
        version = 0;
        compacted = 0;
        last_replicated = 0;
        last_committable = 0;
        rollback_count = 0;
        pending_txs.clear();
      }
    }

    /** This is only safe in very restricted circumstances, and is only
     * meant to be used during catastrophic recovery, between a KV
     * with public-state only and a KV with full state, to swap in the
     * private state from the latter into the former.
     *
     * It's also important to note that swapping in private state
     * may result in previously uncompacted writes becoming effectively
     * compacted, from a user's perspective (they would not be internally
     * compacted until the next compact() however). So it is important to
     * make sure that the private state being swapped in is fully compacted
     * before the swap.
     **/
    void swap_private_maps(Store<S, D>& store)
    {
      std::lock_guard<SpinLock> this_maps_guard(maps_lock);
      std::lock_guard<SpinLock> other_maps_guard(store.maps_lock);

      using MapEntry =
        std::tuple<std::string, AbstractMap<S, D>*, AbstractMap<S, D>*>;
      std::vector<MapEntry> entries;

      for (auto& [name, map] : maps)
      {
        if (map->get_security_domain() == SecurityDomain::PRIVATE)
        {
          map->lock();
          entries.emplace_back(name, map.get(), nullptr);
        }
      }

      auto entry = entries.begin();
      for (auto& [name, map] : store.maps)
      {
        if (map->get_security_domain() == SecurityDomain::PRIVATE)
        {
          if (entry == entries.end())
            throw std::logic_error(
              "Private map list mismatch during swap, " + name + " not found");

          if (std::get<0>(*entry) != name)
            throw std::logic_error(
              "Private map list mismatch during swap, " + std::get<0>(*entry) +
              " != " + name);

          map->lock();
          std::get<2>(*entry) = map.get();

          ++entry;
        }
      }

      if (entry != entries.end())
      {
        throw std::logic_error(
          "Private map list mismatch during swap, missing at least " +
          std::get<0>(*entry));
      }

      for (auto& [name, lhs, rhs] : entries)
      {
        lhs->swap(rhs);
      }

      for (auto& [name, lhs, rhs] : entries)
      {
        lhs->unlock();
        rhs->unlock();
      }
    }
  };
}
