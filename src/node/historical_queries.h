// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "consensus/ledger_enclave_types.h"
#include "kv/store.h"
#include "node/history.h"
#include "node/rpc/node_interface.h"

#include <deque>
#include <map>
#include <memory>

namespace ccf::historical
{
  class StateCache
  {
  protected:
    kv::Store& source_store;
    ringbuffer::WriterPtr to_host;

    // TODO: Add sensible caps on all these containers?
    std::set<consensus::Index> requested_indices;

    static constexpr size_t MAX_PENDING_FETCHES = 10;
    std::deque<consensus::Index> pending_fetches;

    using StorePtr = std::shared_ptr<kv::Store>;
    std::map<consensus::Index, std::pair<StorePtr, crypto::Sha256Hash>>
      untrusted_entries;

    // TODO: Make this an LRU, evict old entries
    std::map<consensus::Index, StorePtr> trusted_entries;

    using LedgerEntry = std::vector<uint8_t>;

    void request_entry_at(consensus::Index idx)
    {
      const auto ib = requested_indices.insert(idx);
      if (ib.second)
      {
        fetch_entry_at(idx);
      }
    }

    void fetch_entry_at(consensus::Index idx)
    {
      if (pending_fetches.size() < MAX_PENDING_FETCHES)
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
        pending_fetches.push_back(idx);
      }

      // Too many outstanding fetches, this one is silently ignored
      // TODO
    }

    std::optional<ccf::Signature> get_signature(const StorePtr& sig_store)
    {
      kv::Tx tx;
      auto sig_table = sig_store->get<ccf::Signatures>(ccf::Tables::SIGNATURES);
      if (sig_table == nullptr)
      {
        throw std::logic_error(
          "Missing signatures table in signature transaction");
      }

      auto sig_view = tx.get_view(*sig_table);
      return sig_view->get(0);
    }

    std::optional<ccf::NodeInfo> get_node_info(ccf::NodeId node_id)
    {
      // Current solution: Use current state of Nodes table from real store.
      // This only works while entries are never deleted from this table, and
      // makes no check that the signing node was active at the point it
      // produced this signature
      kv::Tx tx;

      auto nodes_table = source_store.get<ccf::Nodes>(ccf::Tables::NODES);
      if (nodes_table == nullptr)
      {
        throw std::logic_error("Missing nodes table");
      }

      auto nodes_view = tx.get_view(*nodes_table);
      return nodes_view->get(node_id);
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

      // TODO: Check the signature is produced by the claimed node (needs
      // retrieval of the node's cert)
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
      const auto verified = verifier->verify_hash(
        real_root.h.data(),
        real_root.h.size(),
        sig->sig.data(),
        sig->sig.size());
      if (!verified)
      {
        throw std::logic_error(
          fmt::format("Signature at {} is invalid", sig_idx));
      }

      // TODO: Find which of our untrusted indices are in this tree
      auto it = untrusted_entries.begin();
      while (it != untrusted_entries.end())
      {
        const auto& untrusted_idx = it->first;
        const auto& untrusted_store = it->second.first;
        const auto& untrusted_hash = it->second.second;

        try
        {
          const auto receipt = tree.get_receipt(untrusted_idx);
          LOG_INFO_FMT(
            "From signature at {}, constructed a receipt for {}",
            sig_idx,
            untrusted_idx);

          // TODO: Check that the receipt matches our untrusted entry
          // const auto& entry_hash_in_receipt = receipt.leaf;
          // if (untrusted_hash != entry_hash_in_receipt)
          // {
          //   throw std::logic_error(
          //     fmt::format("Hash mismatch for {}", untrusted_idx));
          // }

          // Move stores from untrusted to trusted
          // TODO: Temp solution, blindly trust everything for now
          const auto trusted_ib =
            trusted_entries.emplace(untrusted_idx, untrusted_store);
          if (trusted_ib.second)
          {
            LOG_INFO_FMT("Now trusting {}", untrusted_idx);
          }
          else
          {
            LOG_INFO_FMT("Already trusted {}", untrusted_idx);
          }
          it = untrusted_entries.erase(it);
        }
        catch (const std::exception& e)
        {
          LOG_INFO_FMT(
            "Signature at {} does not cover {}: {}",
            sig_idx,
            untrusted_idx,
            e.what());
          // TODO: Can we expose "what indices do you cover" through the
          // MerkleTree, rather than try-catch?
          ++it;
          // TODO: Should we abandon this untrusted entry now?
        }
      }
    }

    void deserialise_ledger_entry(
      consensus::Index idx, const LedgerEntry& entry)
    {
      StorePtr store = std::make_shared<kv::Store>();

      store->set_encryptor(source_store.get_encryptor());

      // TODO: Add a lazy clone option?
      store->clone_schema(source_store);
      store->set_strict_versions(false);

      const auto deserialise_result = store->deserialise_views(entry);

      switch (deserialise_result)
      {
        case kv::DeserialiseSuccess::FAILED:
        {
          // TODO: Host gave us junk? Do we fail silently?
          throw std::logic_error("Deserialise failed!");
          break;
        }
        case kv::DeserialiseSuccess::PASS:
        {
          const auto request_it = requested_indices.find(idx);
          if (request_it != requested_indices.end())
          {
            // We were looking for this entry! Store the produced store
            // TODO: Should we check if we already have this? If the host spams
            // us, do we just ignore everything but the first result they give
            // us?
            crypto::Sha256Hash hash(entry);
            untrusted_entries[idx] = std::make_pair(store, hash);
          }

          // In either case, its not a signature - try the next transaction
          fetch_entry_at(idx + 1);
          break;
        }
        case kv::DeserialiseSuccess::PASS_SIGNATURE:
        {
          LOG_INFO_FMT("Found a signature transaction at {}", idx);
          // Hurrah! We can hopefully use this signature to move some old stores
          // from untrusted to trusted!

          handle_signature_transaction(idx, store);
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

    StorePtr get_store_at(consensus::Index idx)
    {
      const auto trusted_it = trusted_entries.find(idx);
      if (trusted_it == trusted_entries.end())
      {
        // Otherwise, treat this as a hint and (potentially) start fetching it
        request_entry_at(idx);

        return nullptr;
      }

      return trusted_it->second;
    }

    bool handle_ledger_entry(consensus::Index idx, const LedgerEntry& data)
    {
      const auto it =
        std::find(pending_fetches.begin(), pending_fetches.end(), idx);
      if (it == pending_fetches.end())
      {
        // TODO
        // Unexpected entry - probably just ignore it?
        return false;
      }

      pending_fetches.erase(it);
      // TODO: Shouldn't throw when the host sends us junk, catch exceptions
      // here?
      deserialise_ledger_entry(idx, data);
      return true;
    }

    void handle_no_entry(consensus::Index idx)
    {
      const auto it =
        std::find(pending_fetches.begin(), pending_fetches.end(), idx);
      if (it == pending_fetches.end())
      {
        // TODO
        // We weren't even expecting this entry - surely just ignore it?
        return;
      }

      // The host failed or refused to gives us this. Currently we just forget
      // about it, we don't have a mechanism for remembering this failure and
      // reporting it to users.
      pending_fetches.erase(it);
    }
  };
}