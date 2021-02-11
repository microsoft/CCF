// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "consensus/ledger_enclave_types.h"
#include "node/historical_queries_interface.h"
#include "node/history.h"
#include "node/ledger_secrets.h"
#include "node/network_state.h"
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
    ccf::NetworkState& network;
    ringbuffer::WriterPtr to_host;

    enum class RequestStage
    {
      RecoveringLedgerSecret,
      Fetching,
      Untrusted,
      Trusted,
    };

    using LedgerEntry = std::vector<uint8_t>;

    // TODO:
    // 1. Should be usable from encryptor
    // 2. Should be thread safe
    // 3. Should be cleared if it becomes too large
    LedgerSecretsMap historical_ledger_secrets;

    struct LedgerSecretRecoveryInfo
    {
      consensus::Index target_idx = 0;
      LedgerSecret last_ledger_secret;

      LedgerSecretRecoveryInfo(const LedgerSecretRecoveryInfo& other) :
        target_idx(other.target_idx),
        last_ledger_secret(other.last_ledger_secret)
      {}

      LedgerSecretRecoveryInfo(
        consensus::Index target_idx_, const LedgerSecret& last_ledger_secret_) :
        target_idx(target_idx_),
        last_ledger_secret(last_ledger_secret_)
      {}
    };

    struct Request
    {
      RequestStage current_stage = RequestStage::Fetching;
      crypto::Sha256Hash entry_hash = {};
      StorePtr store = nullptr;

      // Only set when recovering ledger secrets
      std::unique_ptr<LedgerSecretRecoveryInfo> ledger_secret_recovery_info =
        nullptr;
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

      consensus::Index first_fetched_idx = idx;
      RequestStage request_stage = RequestStage::Fetching;
      std::unique_ptr<LedgerSecretRecoveryInfo> ledger_secret_recovery_info =
        nullptr;

      auto first_known_ledger_secret = network.ledger_secrets->get_first();
      if (idx < static_cast<consensus::Index>(first_known_ledger_secret.first))
      {
        LOG_FAIL_FMT(
          "Requesting historical entry at {} but first known ledger secret is "
          "at {}",
          idx,
          first_known_ledger_secret.first);

        LOG_FAIL_FMT(
          "Requesting entry at {}",
          first_known_ledger_secret.second.previous_secret_stored_version
            .value_or(kv::NoVersion));

        auto previous_secret_stored_version =
          first_known_ledger_secret.second.previous_secret_stored_version;
        if (!previous_secret_stored_version.has_value())
        {
          throw std::logic_error(
            "First known ledger secret has no previous secret stored version!");
        }

        first_fetched_idx = previous_secret_stored_version.value();
        request_stage = RequestStage::RecoveringLedgerSecret;
        ledger_secret_recovery_info =
          std::make_unique<LedgerSecretRecoveryInfo>(
            idx, first_known_ledger_secret.second);
      }

      // Try to insert new request
      const auto ib = requests.insert(std::make_pair(
        first_fetched_idx,
        Request{
          request_stage, {}, nullptr, std::move(ledger_secret_recovery_info)}));
      if (ib.second)
      {
        // If its a new request, begin fetching it
        fetch_entry_at(first_fetched_idx);
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
      auto tx = sig_store->create_read_only_tx();
      auto signatures = tx.ro<ccf::Signatures>(ccf::Tables::SIGNATURES);
      return signatures->get(0);
    }

    std::optional<ccf::NodeInfo> get_node_info(ccf::NodeId node_id)
    {
      // Current solution: Use current state of Nodes table from real store.
      // This only works while entries are never deleted from this table, and
      // makes no check that the signing node was active at the point it
      // produced this signature
      auto tx = network.tables->create_tx();
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
      LOG_FAIL_FMT("Deserialising historical entry at: {}", idx);

      StorePtr store = std::make_shared<kv::Store>(
        false /* Do not start from very first idx */,
        true /* Make use of historical secrets */);

      store->set_encryptor(network.tables->get_encryptor());

      auto request_it = requests.find(idx);
      if (request_it != requests.end())
      {
        auto& request = request_it->second;
        if (request.current_stage == RequestStage::RecoveringLedgerSecret)
        {
          LOG_FAIL_FMT("Recovering ledger secret! Deserialising public...");
          const auto deserialise_result =
            store->apply(entry, ConsensusType::CFT, true)->execute();
          if (deserialise_result == kv::ApplyResult::FAIL)
          {
            throw std::logic_error("Could not deserialise entry");
          }

          // TODO: Verify that we indeed deserialised a ledger secret

          auto tx = store->create_read_only_tx();
          auto encrypted_previous_ledger_secret =
            tx.ro<ccf::EncryptedLedgerSecretsInfo>(
              ccf::Tables::ENCRYPTED_PAST_LEDGER_SECRET);
          if (!encrypted_previous_ledger_secret)
          {
            throw std::logic_error("This isn't a valid ledger secret!");
          }

          LOG_FAIL_FMT("Version of store now: {}", store->current_version());

          auto previous_ledger_secret =
            encrypted_previous_ledger_secret->get(0)->previous_ledger_secret;

          // TODO: Store first known ledger secret in request, and replace every
          // time!
          auto first_known_ledger_secret =
            request.ledger_secret_recovery_info->last_ledger_secret;

          auto ledger_secret = decrypt_previous_ledger_secret(
            first_known_ledger_secret.raw_key,
            std::move(previous_ledger_secret->encrypted_data));

          LOG_FAIL_FMT(
            "Restoring ledger secret valid from {}, and previous one stored at "
            "{}",
            previous_ledger_secret->version,
            previous_ledger_secret->previous_secret_stored_version.value_or(
              kv::NoVersion));

          historical_ledger_secrets.emplace(
            previous_ledger_secret->version,
            LedgerSecret(
              std::move(ledger_secret),
              previous_ledger_secret->previous_secret_stored_version));

          LOG_FAIL_FMT(
            "Decrypted and fetched ledger secret at {}",
            previous_ledger_secret->version);

          if (
            previous_ledger_secret.has_value() &&
            previous_ledger_secret->version <
              static_cast<kv::Version>(
                request.ledger_secret_recovery_info->target_idx))
          {
            LOG_FAIL_FMT(
              "We're done, let's fetch the target idx at {}",
              request.ledger_secret_recovery_info->target_idx);

            request.current_stage = RequestStage::Fetching;
            fetch_entry_at(request.ledger_secret_recovery_info->target_idx);
          }
          else
          {
            LOG_FAIL_FMT("Let's continue fetching entries...");
            fetch_entry_at(
              previous_ledger_secret->previous_secret_stored_version.value());
          }

          return;
        }
      }

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
    StateCache(
      ccf::NetworkState& network_, const ringbuffer::WriterPtr& host_writer) :
      network(network_),
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
