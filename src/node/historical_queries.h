// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "consensus/ledger_enclave_types.h"
#include "ds/spin_lock.h"
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
      consensus::Index last_requested_index;
      std::vector<StoreDetails> stores;
      std::chrono::milliseconds time_to_expiry;

      Request(consensus::Index start_idx, size_t num_following_indices)
      {
        adjust_range(start_idx, num_following_indices);
      }

      bool is_index_in_requested_range(consensus::Index idx)
      {
        return idx >= first_requested_index && idx <= last_requested_index;
      }

      bool does_range_match(
        consensus::Index start_idx, size_t num_following_indices)
      {
        return start_idx == first_requested_index &&
          (stores.size() == num_following_indices + 1);
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
        last_requested_index = first_requested_index + num_following_indices;
        std::set<consensus::Index> ret;
        for (size_t i = start_idx; i <= last_requested_index; ++i)
        {
          ret.insert(i);
        }
        return ret;
      }
    };

    SpinLock requests_lock;

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
    // checks. Modifies requesting_handles on successful return to contain only
    // the handles which are still looking for the next index.
    bool handle_signature_transaction(
      const StorePtr& sig_store,
      consensus::Index sig_idx,
      HandleSet& requesting_handles)
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

      auto handle_it = requesting_handles.begin();
      while (handle_it != requesting_handles.end())
      {
        auto it = requests.find(*handle_it);
        if (it == requests.end())
        {
          handle_it = requesting_handles.erase(handle_it);
          continue;
        }

        Request& request = it->second;

        bool signature_invalidates_request = false;
        bool request_complete = false;

        for (auto requested_idx = request.first_requested_index;
             requested_idx <= request.last_requested_index &&
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

              if (sig_idx >= request.last_requested_index)
              {
                request_complete = true;
              }
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
          request_complete = true;
        }

        // If this signature terminates the requested range, or has invalidated
        // the previous range, we can remove it from requesting_handles
        if (request_complete)
        {
          handle_it = requesting_handles.erase(handle_it);
        }
        else
        {
          ++handle_it;
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

    std::vector<StorePtr> get_store_range_internal(
      RequestHandle handle,
      consensus::Index start_idx,
      size_t num_following_indices,
      ExpiryDuration expire_after)
    {
      const auto expire_after_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(expire_after);

      std::lock_guard<SpinLock> guard(requests_lock);

      auto it = requests.find(handle);
      if (it == requests.end())
      {
        // This is a new handle - create entirely new request object for it
        Request new_request(start_idx, num_following_indices);
        it = requests.emplace_hint(it, handle, std::move(new_request));

        // Start fetching entries
        for (consensus::Index idx = start_idx;
             idx <= start_idx + num_following_indices;
             ++idx)
        {
          fetch_entry_at({handle}, idx);
        }
      }
      else
      {
        // There's an existing request at this handle - modify it if necessary
        // and ensure all requested indices are being fetched
        auto& request = it->second;
        if (!request.does_range_match(start_idx, num_following_indices))
        {
          // We could just consider this equivalent to the case above, but
          // instead we retain old StoreDetails where possible in the same
          // Request, if the previous request and this had some overlap
          auto new_indices =
            request.adjust_range(start_idx, num_following_indices);
          for (const auto new_idx : new_indices)
          {
            fetch_entry_at({handle}, new_idx);
          }
        }
      }

      Request& request = it->second;

      // In any case, reset the expiry time as this has just been requested
      request.time_to_expiry = expire_after_ms;

      std::vector<StorePtr> trusted_stores;

      for (consensus::Index idx = start_idx;
           idx <= start_idx + num_following_indices;
           ++idx)
      {
        auto& target_details = request.get_store_details(idx);
        if (target_details.current_stage == RequestStage::Trusted)
        {
          // Have this store and trust it - add it to return list
          trusted_stores.push_back(target_details.store);
        }
        else
        {
          // Still fetching this store or don't trust it yet, so range is
          // incomplete - return empty vector
          return {};
        }
      }

      return trusted_stores;
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
      auto range = get_store_range(handle, idx, idx, expire_after);
      if (range.empty())
      {
        return nullptr;
      }

      return range[0];
    }

    StorePtr get_store_at(RequestHandle handle, consensus::Index idx) override
    {
      return get_store_at(handle, idx, default_expiry_duration);
    }

    std::vector<StorePtr> get_store_range(
      RequestHandle handle,
      consensus::Index start_idx,
      consensus::Index end_idx,
      ExpiryDuration expire_after) override
    {
      if (end_idx < start_idx)
      {
        throw std::logic_error(fmt::format(
          "Invalid range for historical query: end {} is before start {}",
          end_idx,
          start_idx));
      }

      const auto tail_length = end_idx - start_idx;
      return get_store_range_internal(
        handle, start_idx, tail_length, expire_after);
    }

    std::vector<StorePtr> get_store_range(
      RequestHandle handle,
      consensus::Index start_idx,
      consensus::Index end_idx) override
    {
      return get_store_range(
        handle, start_idx, end_idx, default_expiry_duration);
    }

    void set_default_expiry_duration(ExpiryDuration duration) override
    {
      default_expiry_duration = duration;
    }

    bool drop_request(RequestHandle handle) override
    {
      std::lock_guard<SpinLock> guard(requests_lock);
      const auto erased_count = requests.erase(handle);
      return erased_count > 0;
    }

    bool handle_ledger_entry(consensus::Index idx, const LedgerEntry& data)
    {
      std::lock_guard<SpinLock> guard(requests_lock);
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

      kv::ApplyResult deserialise_result;

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
        deserialise_result = kv::ApplyResult::FAILED;
      }

      if (deserialise_result == kv::ApplyResult::FAILED)
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

      auto handles = it->second;

      if (deserialise_result == kv::ApplyResult::PASS_SIGNATURE)
      {
        // This looks like a valid signature - try to use this signature to
        // move some stores from untrusted to trusted
        handle_signature_transaction(store, idx, handles);
      }

      // If still required to fulfill a range or find the validating signature,
      // fetch the next index
      if (!handles.empty())
      {
        if (deserialise_result == kv::ApplyResult::PASS_SIGNATURE)
        {
          LOG_INFO_FMT(
            "Deserialised a signature at {}, but still have handles looking "
            "for the next index!",
            idx);
        }
        fetch_entry_at(handles, idx + 1);
      }

      pending_fetches.erase(it);

      return true;
    }

    void handle_no_entry(consensus::Index idx)
    {
      std::lock_guard<SpinLock> guard(requests_lock);

      // The host failed or refused to give this entry. Currently just
      // forget about it and drop any requests which were looking for it - don't
      // have a mechanism for remembering this failure and reporting it to
      // users.
      const auto fetches_it = pending_fetches.find(idx);
      if (fetches_it != pending_fetches.end())
      {
        for (auto handle : fetches_it->second)
        {
          requests.erase(handle);
        }

        pending_fetches.erase(fetches_it);
      }
    }

    void tick(const std::chrono::milliseconds& elapsed_ms)
    {
      std::lock_guard<SpinLock> guard(requests_lock);
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
