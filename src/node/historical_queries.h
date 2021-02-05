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
      consensus::Index target_index;
      RequestStage current_stage = RequestStage::Fetching;
      crypto::Sha256Hash entry_hash = {};
      StorePtr store = nullptr;
    };

    // Things actually requested by external callers
    std::map<RequestHandle, Request> requests;

    // Outstanding requested indices. Some will be targets of requests, some
    // will just be surrounding supporting evidence. Stored to enable efficient
    // reverse lookup.
    using HandleSet = std::set<RequestHandle>;
    std::map<consensus::Index, HandleSet> pending_fetches;

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

      LOG_INFO_FMT("AAAA");
      for (const auto handle : requesting_handles)
      {
        LOG_INFO_FMT("Considering handle {}", handle);
        auto it = requests.find(handle);
        if (it == requests.end())
        {
          continue;
        }

        auto& request = it->second;
        const auto untrusted_idx = request.target_index;
        const auto sig_is_requested = (sig_idx == untrusted_idx);

        if (
          request.current_stage == RequestStage::Untrusted &&
          (tree.in_range(untrusted_idx) || sig_is_requested))
        {
          if (!sig_is_requested)
          {
            // Compare signed hash, from signature mini-tree, with hash of the
            // entry which was used to populate the store
            const auto& untrusted_hash = request.entry_hash;
            const auto trusted_hash = tree.get_leaf(untrusted_idx);
            if (trusted_hash != untrusted_hash)
            {
              LOG_FAIL_FMT(
                "Signature at {} has a different transaction at {} than "
                "previously received",
                sig_idx,
                untrusted_idx);
              // We trust the signature but not the store - delete this
              // untrusted store. If it is re-requested, maybe the host will
              // give us a valid pair of transaction+sig next time
              it = requests.erase(it);
              continue;
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
            "Now trusting {} due to signature at {}", untrusted_idx, sig_idx);
          request.current_stage = RequestStage::Trusted;
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
          auto& request = request_it->second;
          if (request.current_stage == RequestStage::Fetching)
          {
            // We were looking for this entry. Store the produced store
            request.current_stage = RequestStage::Untrusted;
            request.entry_hash = entry_hash;
            request.store = store;
          }
          else
          {
            LOG_DEBUG_FMT(
              "Not fetching ledger entry {}: already have it in stage {}",
              request_it->first,
              request.current_stage);
          }
        }
      }
    }

  public:
    StateCache(kv::Store& store, const ringbuffer::WriterPtr& host_writer) :
      source_store(store),
      to_host(host_writer)
    {}

    StorePtr get_store_at(RequestHandle request, consensus::Index idx) override
    {
      // TODO: Lock here, and probably everywhere
      // If this is a new handle, or a new request for an existing handle
      const auto it = requests.find(request);
      if (it == requests.end() || it->second.target_index != idx)
      {
        // Record details of this request
        Request new_request;
        new_request.target_index = idx;
        requests[request] = std::move(new_request);

        // Start fetching it
        fetch_entry_at({request}, idx);

        return nullptr;
      }

      if (it->second.current_stage == RequestStage::Trusted)
      {
        // Have this store and trust it
        return it->second.store;
      }

      // Still fetching this store or don't trust it yet
      return nullptr;
    }

    // TODO: Impl
    void set_default_expiry_duration(ExpiryDuration duration) override {}

    bool set_expiry_duration(
      RequestHandle handle, ExpiryDuration duration) override
    {
      return false;
    }

    bool drop_request(RequestHandle handle) override
    {
      return false;
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
  };
}
