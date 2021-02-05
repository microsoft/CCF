// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "consensus/ledger_enclave_types.h"
#include "kv/store.h"
#include "node/historical_queries_interface.h"
#include "node/history.h"
#include "node/rpc/node_interface.h"

#include <list>
#include <map>
#include <memory>
#include <set>

namespace ccf::historical
{
  class StateCache : public AbstractStateCache
  {
  protected:
    kv::Store& source_store;
    ringbuffer::WriterPtr to_host;

    enum class RequestStage
    {
      Fetching,
      Untrusted,
      Trusted,
    };

    using LedgerEntry = std::vector<uint8_t>;

    struct Request
    {
      struct StoreDetails
      {
        RequestStage current_stage = RequestStage::Fetching;
        crypto::Sha256Hash entry_hash = {};
        StorePtr store = nullptr;
      };

      // To avoid duplicating state, range details are determined by length of
      // stores
      consensus::Index first_requested_index;
      std::vector<StoreDetails> stores;
      std::chrono::milliseconds time_to_expiry;

      Request(consensus::Index start_idx, size_t num_following_indices)
      {
        first_requested_index = start_idx;
        stores.resize(1 + num_following_indices);
      }

      consensus::Index get_requested_index_end()
      {
        // This is an iterator-style end, 1 greater than last()
        return first_requested_index + stores.size();
      }

      bool is_index_in_requested_range(consensus::Index idx)
      {
        const auto end = get_requested_index_end();
        return idx >= first_requested_index && idx < end;
      }

      StoreDetails& get_store_details(consensus::Index idx)
      {
        if (!is_index_in_requested_range(idx))
        {
          throw std::logic_error(
            "Asked for details about an index which is not in this request");
        }

        const auto offset = idx - first_requested_index;
        return stores[offset];
      }

      std::set<consensus::Index> adjust_range(
        consensus::Index start_idx, size_t num_following_indices)
      {
        // TODO: Calculate actual overlap. This just drops everything and says
        // it needs to be refetched
        stores.clear();
        first_requested_index = start_idx;
        stores.resize(1 + num_following_indices);
        std::set<consensus::Index> ret;
        for (size_t i = start_idx; i < get_requested_index_end(); ++i)
        {
          ret.insert(i);
        }
        return ret;
      }
    };

    // Things actually requested by external callers
    std::map<RequestHandle, Request> requests;

    // Outstanding requested indices. Some will be targets of requests, some
    // will just be surrounding supporting evidence. Stored to enable efficient
    // reverse lookup.
    using HandleSet = std::set<RequestHandle>;
    std::map<consensus::Index, HandleSet> pending_fetches;

    ExpiryDuration default_expiry_duration = std::chrono::seconds(1800);

    void fetch_entry_at(const HandleSet& handles, consensus::Index idx)
    {
      auto it = pending_fetches.find(idx);
      if (it != pending_fetches.end())
      {
        // Already fetching this index - record all _new_ handles which are
        // waiting for it
        it->second.insert(handles.begin(), handles.end());
        return;
      }

      // Begin fetching, and record who we're fetching for
      pending_fetches.emplace_hint(it, idx, handles);
      RINGBUFFER_WRITE_MESSAGE(
        consensus::ledger_get,
        to_host,
        idx,
        consensus::LedgerRequestPurpose::HistoricalQuery);
    }

    std::optional<ccf::PrimarySignature> get_signature(
      const StorePtr& sig_store)
    {
      auto tx = sig_store->create_tx();
      auto signatures = tx.ro<ccf::Signatures>(ccf::Tables::SIGNATURES);
      return signatures->get(0);
    }

    std::optional<ccf::NodeInfo> get_node_info(ccf::NodeId node_id)
    {
      // Current solution: Use current state of Nodes table from real store.
      // This only works while entries are never deleted from this table, and
      // makes no check that the signing node was active at the point it
      // produced this signature
      auto tx = source_store.create_tx();
      auto nodes = tx.ro<ccf::Nodes>(ccf::Tables::NODES);
      return nodes->get(node_id);
    }

    // Returns true if this is a valid signature that passes our verification
    // checks
    bool handle_signature_transaction(
      const StorePtr& sig_store,
      consensus::Index sig_idx,
      const HandleSet& requesting_handles)
    {
      const auto sig = get_signature(sig_store);
      if (!sig.has_value())
      {
        LOG_FAIL_FMT("Signature at {}: Missing signature value", sig_idx);
        return false;
      }

      // Build tree from signature
      ccf::MerkleTreeHistory tree(sig->tree);
      const auto real_root = tree.get_root();
      if (real_root != sig->root)
      {
        LOG_FAIL_FMT("Signature at {}: Invalid root", sig_idx);
        return false;
      }

      const auto node_info = get_node_info(sig->node);
      if (!node_info.has_value())
      {
        LOG_FAIL_FMT("Signature at {}: Node {} is unknown", sig_idx, sig->node);
        return false;
      }

      auto verifier = tls::make_verifier(node_info->cert);
      const auto verified = verifier->verify_hash(
        real_root.h.data(),
        real_root.h.size(),
        sig->sig.data(),
        sig->sig.size());
      if (!verified)
      {
        LOG_FAIL_FMT("Signature at {}: Signature invalid", sig_idx);
        return false;
      }

      for (const auto handle : requesting_handles)
      {
        auto it = requests.find(handle);
        if (it == requests.end())
        {
          continue;
        }

        Request& request = it->second;

        bool signature_invalidates_request = false;

        for (auto requested_idx = request.first_requested_index;
             requested_idx < request.get_requested_index_end() &&
             !signature_invalidates_request;
             ++requested_idx)
        {
          const auto sig_is_requested = (sig_idx == requested_idx);
          if (tree.in_range(requested_idx) || sig_is_requested)
          {
            auto& details = request.get_store_details(requested_idx);
            if (details.current_stage == RequestStage::Untrusted)
            {
              if (!sig_is_requested)
              {
                // Compare signed hash, from signature mini-tree, with hash of
                // the entry which was used to populate the store
                const auto& untrusted_hash = details.entry_hash;
                const auto trusted_hash = tree.get_leaf(requested_idx);
                if (trusted_hash != untrusted_hash)
                {
                  LOG_FAIL_FMT(
                    "Signature at {} has a different transaction at {} than "
                    "previously received",
                    sig_idx,
                    requested_idx);

                  signature_invalidates_request = true;
                  break;
                }
              }
              else
              {
                // We already trust this transaction (it contains a signature
                // written by a node we trust, and nothing else) so don't have
                // anything further to validate
              }

              // Move store from untrusted to trusted
              LOG_DEBUG_FMT(
                "Now trusting {} due to signature at {}",
                requested_idx,
                sig_idx);
              details.current_stage = RequestStage::Trusted;
            }
          }
        }

        // We trust the signature (since it comes from a trusted node), and it
        // disagrees with one of the entries we previously retrieved and
        // deserialised. This generally means a malicious host gave us a good
        // transaction but a good signature. Delete the entire original request
        // - if it is re-requested, maybe the host will give us a valid pair of
        // transaction+sig next time
        if (signature_invalidates_request)
        {
          it = requests.erase(it);
        }
      }

      return true;
    }

    void process_deserialised_store(
      const StorePtr& store,
      const crypto::Sha256Hash& entry_hash,
      consensus::Index idx,
      const HandleSet& requesting_handles)
    {
      for (const auto handle : requesting_handles)
      {
        auto request_it = requests.find(handle);
        if (request_it != requests.end())
        {
          Request& request = request_it->second;
          if (request.is_index_in_requested_range(idx))
          {
            auto& details = request.get_store_details(idx);
            if (details.current_stage == RequestStage::Fetching)
            {
              // We were looking for this entry. Store the produced store
              details.current_stage = RequestStage::Untrusted;
              details.entry_hash = entry_hash;
              details.store = store;
            }
            else
            {
              LOG_DEBUG_FMT(
                "Request {} is not fetching ledger entry {}: already have it "
                "in stage {}",
                handle,
                idx,
                details.current_stage);
            }
          }
        }
      }
    }

  public:
    StateCache(kv::Store& store, const ringbuffer::WriterPtr& host_writer) :
      source_store(store),
      to_host(host_writer)
    {}

    StorePtr get_store_at(
      RequestHandle handle,
      consensus::Index idx,
      ExpiryDuration expire_after) override
    {
      const auto expire_after_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(expire_after);

      // If this is a new handle, or a new request for an existing handle
      auto it = requests.find(handle);
      if (it == requests.end())
      {
        // This is a new handle - create entirely new request object for it
        Request new_request(idx, 0);
        it = requests.emplace_hint(it, handle, std::move(new_request));

        // Start fetching it
        fetch_entry_at({handle}, idx);
      }
      else
      {
        // There's an existing request at this handle - modify it if necessary
        // and ensure all requested indices are being fetched
        auto& request = it->second;
        if (!request.is_index_in_requested_range(idx))
        {
          // We could just consider this equivalent to the case above, but
          // instead we retain old StoreDetails where possible in the same
          // Request, if the previous request and this had some overlap
          auto new_indices = request.adjust_range(idx, 0);
          for (const auto new_idx : new_indices)
          {
            fetch_entry_at({handle}, new_idx);
          }
        }
      }

      Request& request = it->second;

      // In any case, reset the expiry time as this has just been requested
      request.time_to_expiry = expire_after_ms;

      auto& target_details = request.get_store_details(idx);
      if (target_details.current_stage == RequestStage::Trusted)
      {
        // Have this store and trust it - return it
        return target_details.store;
      }

      // Still fetching this store or don't trust it yet
      return nullptr;
    }

    StorePtr get_store_at(RequestHandle request, consensus::Index idx) override
    {
      return get_store_at(request, idx, default_expiry_duration);
    }

    void set_default_expiry_duration(ExpiryDuration duration) override
    {
      default_expiry_duration = duration;
    }

    bool drop_request(RequestHandle handle) override
    {
      const auto erased_count = requests.erase(handle);
      return erased_count > 0;
    }

    bool handle_ledger_entry(consensus::Index idx, const LedgerEntry& data)
    {
      const auto it = pending_fetches.find(idx);
      if (it == pending_fetches.end())
      {
        // Unexpected entry - ignore it?
        return false;
      }

      // Create a new store and try to deserialise this entry into it
      StorePtr store = std::make_shared<kv::Store>(
        false /* Do not start from very first idx */,
        true /* Make use of historical secrets */);
      store->set_encryptor(source_store.get_encryptor());

      kv::ApplySuccess deserialise_result;

      try
      {
        deserialise_result = store->apply(data, ConsensusType::CFT)->execute();
      }
      catch (const std::exception& e)
      {
        LOG_FAIL_FMT(
          "Exception while attempting to deserialise entry {}: {}",
          idx,
          e.what());
        deserialise_result = kv::ApplySuccess::FAILED;
      }

      if (deserialise_result == kv::ApplySuccess::FAILED)
      {
        pending_fetches.erase(it);
        return false;
      }

      LOG_DEBUG_FMT(
        "Processing historical store at {} ({})",
        idx,
        (size_t)deserialise_result);
      const auto entry_hash = crypto::Sha256Hash(data);
      process_deserialised_store(store, entry_hash, idx, it->second);

      if (deserialise_result == kv::ApplySuccess::PASS_SIGNATURE)
      {
        // This looks like a valid signature - try to use this signature to
        // move some stores from untrusted to trusted
        handle_signature_transaction(store, idx, it->second);
      }
      else
      {
        // This is not a signature - try the next transaction
        fetch_entry_at(it->second, idx + 1);
      }

      pending_fetches.erase(it);

      return true;
    }

    void handle_no_entry(consensus::Index idx)
    {
      // TODO: Can do this more efficiently now pending_fetches is a reverse
      // lookup The host failed or refused to give this entry. Currently just
      // forget about it - don't have a mechanism for remembering this failure
      // and reporting it to users.
      const auto was_fetching = pending_fetches.erase(idx);

      if (was_fetching)
      {
        // To remove requests which were looking for this we need to iterate
        // through all, so only do this if we were actually fetching
        // TODO: What do we do in the range-query case, if an entry is missing?
        // Very tempted to just drop all the work we may have done, assume this
        // is a malicious host or an uncommitted suffix, and we don't want to
        // waste any more time retrying. But we leave orphans if deserialise
        // throws, maybe we need to do that here too? std::erase_if(requests,
        // [idx](const auto& item) {
        //   const auto& [handle, request] = item;
        //   return request.target_index == idx;
        // });
      }
    }

    void tick(const std::chrono::milliseconds& elapsed_ms)
    {
      auto it = requests.begin();
      while (it != requests.end())
      {
        auto& request = it->second;
        if (elapsed_ms >= request.time_to_expiry)
        {
          it = requests.erase(it);
        }
        else
        {
          request.time_to_expiry -= elapsed_ms;
          ++it;
        }
      }
    }
  };
}
