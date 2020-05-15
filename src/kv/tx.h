// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "kv_types.h"
#include "map.h"

namespace kv
{
  class Tx : public ViewContainer
  {
  private:
    OrderedViews view_list;
    bool committed;
    bool success;
    Version read_version;
    Version version;

    kv::TxHistory::RequestID req_id;

    template <class M>
    std::tuple<typename M::TxView*> get_tuple(M& m)
    {
      // If the M is present, its AbtractTxView must be an M::TxView.
      auto search = view_list.find(m.get_name());
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
        read_version = m.get_store()->current_version();
      }

      typename M::TxView* view = m.create_view(read_version);
      view_list[m.get_name()] = {&m, std::unique_ptr<AbstractTxView>(view)};
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

    void set_view_list(OrderedViews& view_list_) override
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
      auto c =
        apply_views(view_list, [store]() { return store->next_version(); });
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

      auto c = apply_views(view_list, [this]() { return version; });
      success = c.has_value();

      if (!success)
        throw std::logic_error("Failed to commit reserved transaction");

      return {CommitSuccess::OK, {0, 0, 0}, std::move(serialise())};
    }
  };
}