// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "consensus/ledger_enclave_types.h"
#include "ds/ccf_assert.h"
#include "ds/spin_lock.h"
#include "node/encryptor.h"
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

    std::shared_ptr<ccf::LedgerSecrets> historical_ledger_secrets;
    std::shared_ptr<ccf::NodeEncryptor> historical_encryptor;

    enum class RequestStage
    {
      RecoveringLedgerSecret,
      Fetching,
      Untrusted,
      Trusted,
    };

    using LedgerEntry = std::vector<uint8_t>;

    struct LedgerSecretRecoveryInfo
    {
      consensus::Index target_idx = 0;
      LedgerSecretPtr last_ledger_secret;

      LedgerSecretRecoveryInfo(
        consensus::Index target_idx_, LedgerSecretPtr last_ledger_secret_) :
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

    using Requests = std::map<consensus::Index, Request>;
    Requests requests;
    std::list<consensus::Index> recent_requests;

    // To trust an index, we currently need to fetch a sequence of entries
    // around it - these aren't user requests, so we don't store them, but we do
    // need to distinguish things-we-asked-for from junk-from-the-host
    std::set<consensus::Index> pending_fetches;

    ccf::VersionedLedgerSecret get_first_known_ledger_secret()
    {
      if (historical_ledger_secrets->is_empty())
      {
        return network.ledger_secrets->get_first();
      }

      auto tx = network.tables->create_read_only_tx();
      CCF_ASSERT_FMT(
        historical_ledger_secrets->get_latest(tx).first <
          network.ledger_secrets->get_first().first,
        "Historical ledger secrets are not older than main ledger secrets");

      return historical_ledger_secrets->get_first();
    }

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

      Request request;
      request.current_stage = RequestStage::Fetching;
      consensus::Index first_idx_to_fetch = idx;

      // If the target historical entry cannot be deserialised with the first
      // known ledger secret, record the target idx and fetch the previous
      // historical ledger secret.
      auto [first_ledger_secret_idx, first_ledger_secret] =
        get_first_known_ledger_secret();
      if (idx < static_cast<consensus::Index>(first_ledger_secret_idx))
      {
        LOG_TRACE_FMT(
          "Requesting historical entry at {} but first known ledger secret is "
          "applicable from {}",
          idx,
          first_ledger_secret_idx);

        auto previous_secret_stored_version =
          first_ledger_secret->previous_secret_stored_version;
        if (!previous_secret_stored_version.has_value())
        {
          throw std::logic_error(fmt::format(
            "First known ledger secret at {} has no previous secret stored "
            "version",
            first_ledger_secret_idx));
        }

        first_idx_to_fetch = previous_secret_stored_version.value();
        request.current_stage = RequestStage::RecoveringLedgerSecret;
        request.ledger_secret_recovery_info =
          std::make_unique<LedgerSecretRecoveryInfo>(idx, first_ledger_secret);
      }

      const auto ib = requests.emplace(first_idx_to_fetch, std::move(request));
      if (ib.second)
      {
        // If its a new request, begin fetching it
        fetch_entry_at(first_idx_to_fetch);
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
      auto tx = network.tables->create_read_only_tx();
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

    Requests::value_type handle_encrypted_past_ledger_secret(
      consensus::Index idx,
      std::unique_ptr<LedgerSecretRecoveryInfo>&& ledger_secret_recovery_info,
      const StorePtr& store)
    {
      auto tx = store->create_read_only_tx();
      auto encrypted_past_ledger_secret =
        tx.ro<ccf::EncryptedLedgerSecretsInfo>(
          ccf::Tables::ENCRYPTED_PAST_LEDGER_SECRET);
      if (!encrypted_past_ledger_secret)
      {
        throw std::logic_error(
          fmt::format("No encrypted ledger secret to read at {}", idx));
      }

      auto previous_ledger_secret =
        encrypted_past_ledger_secret->get(0)->previous_ledger_secret;

      auto recovered_ledger_secret_raw = decrypt_previous_ledger_secret_raw(
        ledger_secret_recovery_info->last_ledger_secret,
        std::move(previous_ledger_secret->encrypted_data));

      auto recovered_ledger_secret = std::make_shared<LedgerSecret>(
        std::move(recovered_ledger_secret_raw),
        previous_ledger_secret->previous_secret_stored_version);

      Request next_request;
      consensus::Index next_idx;

      if (
        previous_ledger_secret.has_value() &&
        previous_ledger_secret->version <=
          static_cast<kv::Version>(ledger_secret_recovery_info->target_idx))
      {
        // All ledger secrets required to deserialise the target index have
        // been fetched so fetch the target entry.

        next_request.current_stage = RequestStage::Fetching;
        next_idx = ledger_secret_recovery_info->target_idx;
      }
      else
      {
        // The previous ledger secret still needs to be fetched.

        // Store first known ledger secret in request, so that
        // we can deserialise the next fetched encrypted ledger secret
        ledger_secret_recovery_info->last_ledger_secret =
          recovered_ledger_secret;

        next_request.current_stage = RequestStage::RecoveringLedgerSecret;
        next_idx =
          previous_ledger_secret->previous_secret_stored_version.value();
        next_request.ledger_secret_recovery_info =
          std::move(ledger_secret_recovery_info);
      }

      historical_ledger_secrets->set_secret(
        previous_ledger_secret->version, std::move(recovered_ledger_secret));

      return std::make_pair(next_idx, std::move(next_request));
    }

    void deserialise_ledger_entry(
      consensus::Index idx, const LedgerEntry& entry)
    {
      StorePtr store = std::make_shared<kv::Store>(
        false /* Do not start from very first idx */,
        true /* Make use of historical secrets */);

      if (
        idx < static_cast<consensus::Index>(
                network.ledger_secrets->get_first().first))
      {
        store->set_encryptor(historical_encryptor);
      }
      else
      {
        store->set_encryptor(network.tables->get_encryptor());
      }

      auto request_it = requests.find(idx);
      if (
        request_it != requests.end() &&
        request_it->second.current_stage ==
          RequestStage::RecoveringLedgerSecret)
      {
        // Encrypted ledger secrets are deserialised in public-only mode.
        // Their Merkle tree integrity is not verified: even if the
        // recovered ledger secret was bogus, the deserialisation of
        // subsequent ledger entries would fail.
        const auto deserialise_result =
          store->apply(entry, ConsensusType::CFT, true)->execute();
        if (deserialise_result == kv::ApplyResult::FAIL)
        {
          throw std::logic_error(fmt::format(
            "Could not deserialise recovered ledger secret entry at {}", idx));
        }

        if (
          deserialise_result !=
          kv::ApplyResult::PASS_ENCRYPTED_PAST_LEDGER_SECRET)
        {
          throw std::logic_error(fmt::format(
            "Recovered ledger entry at {} is not an encrypted ledger secret",
            idx));
        }

        auto new_request = handle_encrypted_past_ledger_secret(
          idx,
          std::move(request_it->second.ledger_secret_recovery_info),
          store);
        const auto ib = requests.emplace(std::move(new_request));
        if (ib.second)
        {
          fetch_entry_at(ib.first->first);
        }
        requests.erase(request_it);
        return;
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
        case kv::ApplyResult::PASS_ENCRYPTED_PAST_LEDGER_SECRET:
        {
          LOG_DEBUG_FMT("Processed transaction at {}", idx);

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
            // This looks like a valid signature - try to use this signature
            // to move some stores from untrusted to trusted
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
      to_host(host_writer),
      historical_ledger_secrets(std::make_shared<ccf::LedgerSecrets>()),
      historical_encryptor(
        std::make_shared<ccf::NodeEncryptor>(historical_ledger_secrets))
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
