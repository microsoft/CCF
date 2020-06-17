// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "kv_serialiser.h"
#include "kv_types.h"
#include "map.h"
#include "view_containers.h"

namespace kv
{
  template <template <typename M> typename GetView>
  class GenericTx : public AbstractViewContainer
  {
  private:
    OrderedViews view_list;
    bool committed = false;
    bool success = false;
    Version read_version = NoVersion;
    Version version = NoVersion;
    Term term = 0;

    kv::TxHistory::RequestID req_id;

    template <class M>
    std::tuple<GetView<M>*> get_tuple(M& m)
    {
      using MapView = GetView<M>;

      // If the M is present, its AbstractTxView should be an M::TxView. This
      // invariant could be broken by set_view_list, which will produce an error
      // here
      auto search = view_list.find(m.get_name());
      if (search != view_list.end())
      {
        auto view = dynamic_cast<MapView*>(search->second.view.get());

        if (view == nullptr)
        {
          throw std::logic_error(fmt::format(
            "View over map {} is not of expected type", m.get_name()));
        }

        return std::make_tuple(view);
      }

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
        auto txid = m.get_store()->current_txid();
        term = txid.term;
        read_version = txid.version;
      }

      MapView* typed_view = m.template create_view<MapView>(read_version);
      auto abstract_view = dynamic_cast<AbstractTxView*>(typed_view);
      if (abstract_view == nullptr)
      {
        throw std::logic_error(fmt::format(
          "View over map {} is not an AbstractTxView", m.get_name()));
      }
      view_list[m.get_name()] = {
        &m, std::unique_ptr<AbstractTxView>(abstract_view)};
      return std::make_tuple(typed_view);
    }

    template <class M, class... Ms>
    std::tuple<GetView<M>*, GetView<Ms>*...> get_tuple(M& m, Ms&... ms)
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
      term = 0;
    }

  public:
    GenericTx() : view_list() {}

    GenericTx(const GenericTx& that) = delete;

    void set_view_list(OrderedViews& view_list_, Term term_) override
    {
      // if view list is not empty then any coinciding keys will not be
      // overwritten
      view_list.merge(view_list_);
      term = term_;
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

    Version get_term()
    {
      return term;
    }

    /** Get a transaction view on a map.
     *
     * This adds the map to the transaction set if it is not yet present.
     *
     * @param m Map
     */
    template <class M>
    GetView<M>* get_view(M& m)
    {
      return std::get<0>(get_tuple(m));
    }

    /** Get transaction views over multiple maps.
     *
     * @param m Map
     * @param ms Map
     */
    template <class M, class... Ms>
    std::tuple<GetView<M>*, GetView<Ms>*...> get_view(M& m, Ms&... ms)
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
            {term, version},
            MovePendingTx(std::move(data), std::move(req_id)),
            false);
        }
        catch (const std::exception& e)
        {
          committed = false;

          LOG_FAIL_FMT("Error during serialisation");
          LOG_DEBUG_FMT("Error during serialisation: {}", e.what());

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

    /** Commit term if committed
     *
     * @return Commit term
     */
    Version commit_term()
    {
      if (!committed)
        throw std::logic_error("Transaction not yet committed");

      if (!success)
        throw std::logic_error("Transaction aborted");

      return term;
    }

    std::vector<uint8_t> serialise(bool include_reads = false)
    {
      if (!committed)
        throw std::logic_error("Transaction not yet committed");

      if (!success)
        throw std::logic_error("Transaction aborted");

      // If no transactions made changes, return a zero length vector.
      const bool any_changes =
        std::any_of(view_list.begin(), view_list.end(), [](const auto& it) {
          return it.second.view->has_changes();
        });

      if (!any_changes)
      {
        return {};
      }

      // Retrieve encryptor.
      auto map = view_list.begin()->second.map;
      auto e = map->get_store()->get_encryptor();

      KvStoreSerialiser replicated_serialiser(e, version);

      // Process in security domain order
      for (auto domain : {SecurityDomain::PUBLIC, SecurityDomain::PRIVATE})
      {
        for (const auto& it : view_list)
        {
          const auto map = it.second.map;
          if (
            map->get_security_domain() == domain && map->is_replicated() &&
            it.second.view->has_changes())
          {
            map->serialise(
              it.second.view.get(), replicated_serialiser, include_reads);
          }
        }
      }

      // Return serialised Tx.
      return replicated_serialiser.get_raw_data();
    }

    // Used by frontend for reserved transactions
    GenericTx(Version reserved) :
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

  namespace details
  {
    template <typename M>
    using GetWriteableView = typename M::TxView;

    template <typename M>
    using GetReadOnlyView = typename M::ReadOnlyTxView;
  };

  // The most common type of Tx creates TxViews which can be used for reads and
  // writes
  class Tx : public GenericTx<details::GetWriteableView>
  {
    using Base = GenericTx<details::GetWriteableView>;

  public:
    using Base::Base;
  };

  // If we know at construction that a Tx will only read, we can create an
  // TrueReadOnlyTx. It creates and stores ReadOnlyTxViews, which have no
  // write functions
  class TrueReadOnlyTx : public GenericTx<details::GetReadOnlyView>
  {
    using Base = GenericTx<details::GetReadOnlyView>;

  public:
    using Base::Base;
  };

  // If we have a maybe-writing Tx that we want to present as ReadOnly, use
  // WrapperReadOnlyTx. It wraps an underlying Tx, and casts the views it
  // returns. This can only be used for get_view - every other operation should
  // be done on the wrapped Tx
  class WrapperReadOnlyTx
  {
  protected:
    Tx& tx;

    template <typename M>
    using GetView = details::GetReadOnlyView<M>;

    template <class M>
    std::tuple<GetView<M>*> get_ro_tuple(M& m)
    {
      return tx.get_view(m);
    }

    template <class M, class... Ms>
    std::tuple<GetView<M>*, GetView<Ms>*...> get_ro_tuple(M& m, Ms&... ms)
    {
      return std::tuple_cat(get_ro_tuple(m), get_ro_tuple(ms...));
    }

  public:
    WrapperReadOnlyTx(Tx& tx_) : tx(tx_) {}

    template <class M>
    GetView<M>* get_view(M& m)
    {
      return std::get<0>(get_ro_tuple(m));
    }

    template <class M, class... Ms>
    std::tuple<GetView<M>*, GetView<Ms>*...> get_view(M& m, Ms&... ms)
    {
      return std::tuple_cat(get_ro_tuple(m), get_ro_tuple(ms...));
    }
  };

  using ReadOnlyTx = WrapperReadOnlyTx;
}
