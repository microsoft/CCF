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
      RequestStage current_stage = RequestStage::Fetching;
      crypto::Sha256Hash entry_hash = {};
      StorePtr store = nullptr;
    };

    // These constitute a simple LRU, where only user queries will refresh an
    // entry's priority
    static constexpr size_t MAX_ACTIVE_REQUESTS = 10;
    std::map<consensus::Index, Request> requests;
    std::list<consensus::Index> recent_requests;

    // To trust an index, we currently need to fetch a sequence of entries
    // around it - these aren't user requests, so we don't store them, but we do
    // need to distinguish things-we-asked-for from junk-from-the-host
    std::set<consensus::Index> pending_fetches;

    void request_entry_at(consensus::Index idx)
    {
      // To avoid duplicates, remove index if it was already requested
      recent_requests.remove(idx);

      // Add request to front of list, most recently requested
      recent_requests.emplace_front(idx);

      // Cull old requests
      while (recent_requests.size() > MAX_ACTIVE_REQUESTS)
      {
        const auto old_idx = recent_requests.back();
        recent_requests.pop_back();
        requests.erase(old_idx);
      }

      // Try to insert new request
      const auto ib = requests.insert(std::make_pair(idx, Request{}));
      if (ib.second)
      {
        // If its a new request, begin fetching it
        fetch_entry_at(idx);
      }
    }

    void fetch_entry_at(consensus::Index idx)
    {
      const auto it =
        std::find(pending_fetches.begin(), pending_fetches.end(), idx);
      if (it != pending_fetches.end())
      {
        // Already fetching this index
        return;
      }

      RINGBUFFER_WRITE_MESSAGE(
        consensus::ledger_get,
        to_host,
        idx,
        consensus::LedgerRequestPurpose::HistoricalQuery);
      pending_fetches.insert(idx);
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

    void handle_signature_transaction(
      consensus::Index sig_idx, const StorePtr& sig_store)
    {
      const auto sig = get_signature(sig_store);
      if (!sig.has_value())
      {
        throw std::logic_error(
          "Missing signature value in signature transaction");
      }

      // Build tree from signature
      ccf::MerkleTreeHistory tree(sig->tree);
      const auto real_root = tree.get_root();
      if (real_root != sig->root)
      {
        throw std::logic_error("Invalid signature: invalid root");
      }

      const auto node_info = get_node_info(sig->node);
      if (!node_info.has_value())
      {
        throw std::logic_error(fmt::format(
          "Signature {} claims it was produced by node {}: This node is "
          "unknown",
          sig_idx,
          sig->node));
      }

      auto verifier = tls::make_verifier(node_info->cert);
      const auto verified =
        verifier->verify_hash(real_root.h, sig->sig, MDType::SHA256);
      if (!verified)
      {
        throw std::logic_error(
          fmt::format("Signature at {} is invalid", sig_idx));
      }

      auto it = requests.begin();
      while (it != requests.end())
      {
        auto& request = it->second;
        const auto& untrusted_idx = it->first;
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
          ++it;
        }
        else
        {
          // Already trusted or still fetching, or this signature doesn't cover
          // this transaction - skip it and try the next
          ++it;
        }
      }
    }

    void deserialise_ledger_entry(
      consensus::Index idx, const LedgerEntry& entry)
    {
      StorePtr store = std::make_shared<kv::Store>(
        false /* Do not start from very first idx */,
        true /* Make use of historical secrets */);

      store->set_encryptor(source_store.get_encryptor());
      const auto deserialise_result =
        store->apply(entry, ConsensusType::CFT)->execute();

      switch (deserialise_result)
      {
        case kv::ApplyResult::FAIL:
        {
          throw std::logic_error("Deserialise failed!");
          break;
        }
        case kv::ApplyResult::PASS:
        case kv::ApplyResult::PASS_SIGNATURE:
        case kv::ApplyResult::PASS_BACKUP_SIGNATURE:
        case kv::ApplyResult::PASS_BACKUP_SIGNATURE_SEND_ACK:
        case kv::ApplyResult::PASS_NONCES:
        case kv::ApplyResult::PASS_NEW_VIEW:
        case kv::ApplyResult::PASS_SNAPSHOT_EVIDENCE:
        {
          LOG_DEBUG_FMT("Processed transaction at {}", idx);

          auto request_it = requests.find(idx);
          if (request_it != requests.end())
          {
            auto& request = request_it->second;
            if (request.current_stage == RequestStage::Fetching)
            {
              // We were looking for this entry. Store the produced store
              request.current_stage = RequestStage::Untrusted;
              request.entry_hash = crypto::Sha256Hash(entry);
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

          if (deserialise_result == kv::ApplyResult::PASS_SIGNATURE)
          {
            // This looks like a valid signature - try to use this signature to
            // move some stores from untrusted to trusted
            handle_signature_transaction(idx, store);
          }
          else
          {
            // This is not a signature - try the next transaction
            fetch_entry_at(idx + 1);
          }
          break;
        }
        default:
        {
          throw std::logic_error("Unexpected deserialise result");
        }
      }
    }

  public:
    StateCache(kv::Store& store, const ringbuffer::WriterPtr& host_writer) :
      source_store(store),
      to_host(host_writer)
    {}

    StorePtr get_store_at(consensus::Index idx) override
    {
      const auto it = requests.find(idx);
      if (it == requests.end())
      {
        // Treat this as a hint and start fetching it
        request_entry_at(idx);

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

    bool handle_ledger_entry(consensus::Index idx, const LedgerEntry& data)
    {
      const auto it =
        std::find(pending_fetches.begin(), pending_fetches.end(), idx);
      if (it == pending_fetches.end())
      {
        // Unexpected entry - ignore it?
        return false;
      }

      pending_fetches.erase(it);

      try
      {
        deserialise_ledger_entry(idx, data);
      }
      catch (const std::exception& e)
      {
        LOG_FAIL_FMT("Unable to deserialise entry {}: {}", idx, e.what());
        return false;
      }

      return true;
    }

    void handle_no_entry(consensus::Index idx)
    {
      const auto request_it = requests.find(idx);
      if (request_it != requests.end())
      {
        if (request_it->second.current_stage == RequestStage::Fetching)
        {
          requests.erase(request_it);
        }
      }

      // The host failed or refused to give this entry. Currently just forget
      // about it - don't have a mechanism for remembering this failure and
      // reporting it to users.
      pending_fetches.erase(idx);
    }
  };
}
